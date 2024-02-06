#include "loop_fetcher.hpp"

using namespace std;

// Optimised representation of CFG to speed up algorithms.
#define INLINED_CHILDREN 2
struct graph_node;
using graph = vector<graph_node>;
using graph_id = vector<graph_node>::size_type;
constexpr graph_id GRAPH_INVALID = graph_id(-1);
struct graph_node {
    address addr;
    graph_id inlined_children[INLINED_CHILDREN] = { GRAPH_INVALID, GRAPH_INVALID };
    vector<graph_id> children;
    cfg_node *node;
    bool is_call;

    graph_node(address addr, cfg_node *node) : addr(addr), node(node), is_call(node->is_call) {}

    void add_child(const graph_id id) {
        bool found(false);
        for (int i = 0; i < INLINED_CHILDREN; i++) {
            if (inlined_children[i] == GRAPH_INVALID) {
                inlined_children[i] = id;
                found = true;
                break;
            }
        }
        if (!found)
            children.push_back(id);
    }
    // iterator for a graph node that iterates over its children
    class const_iterator {
    private:
        const struct graph_node &node;
        size_t position;
    public:
        const_iterator(const struct graph_node &node)
            : node(node), position(-1)
        {
            ++(*this);
        }
        const_iterator(const struct graph_node &node, size_t position)
            : node(node), position(position) { }

        const graph_id &operator*() const {
            if (position < INLINED_CHILDREN)
                return node.inlined_children[position];
            return node.children[position - INLINED_CHILDREN];
        }
        bool operator==(const const_iterator &other) const {
            return other.position == position;
        }
        bool operator!=(const const_iterator &other) const {
            return other.position != position;
        }
        const_iterator &operator++() {
            do {
                ++position;
            } while (
                position < INLINED_CHILDREN &&
                node.inlined_children[position] == GRAPH_INVALID
            );
            return *this;
        }
    };

    const_iterator begin() const { return const_iterator(*this); }
    const_iterator end() const {
        return const_iterator(*this, children.size() + INLINED_CHILDREN);
    }
};

/* DFS, outputting result to list */
void DFS_internal(const graph_id v, const graph_id except, const graph& cfg, vector<bool>& visited) {
    visited.at(v) = true;
    const graph_node &node = cfg.at(v);

    for (auto child: node) {
        if (child == except) continue;
        if (!visited.at(child))
            DFS_internal(child, except, cfg, visited);
    }
}

vector<bool> DFS(const graph_id v, const graph_id except, const graph& cfg) {
    vector<bool> visited;
    visited.resize(cfg.size());
    DFS_internal(v, except, cfg, visited);
    return visited;
}

graph reverse_graph(const graph& cfg) {
    graph recfg;
    recfg.reserve(cfg.size());
    for (const graph_node &node : cfg) {
        recfg.emplace_back(node.addr, node.node);
    }
    graph_id id(0);
    for (const graph_node &node : cfg) {
        for (auto child : node) {
            graph_node &child_node(recfg.at(child));
            child_node.add_child(id);
        }
        id++;
    }
    return recfg;
}

pair<graph, map<address, graph_id>> create_graph(const dycfg &cfg, dycfg &true_cfg) {
    pair<graph, map<address, graph_id>> ret;
    graph &graph = ret.first;
    map<address, graph_id> &node_map = ret.second;
    graph.reserve(cfg.size());
    graph_id id(0);
    for (auto &itr: true_cfg) {
        node_map[itr.first] = id;
        graph.emplace_back(itr.first, &itr.second);
        auto &node = graph.at(id);
        auto child_count = cfg.at(itr.first).child.size();
        node.children.reserve(child_count > INLINED_CHILDREN ? child_count - INLINED_CHILDREN : 0);
        id++;
    }
    for (id = 0; id < graph.size(); id++) {
        auto &node = graph.at(id);
        for (auto child: cfg.at(node.addr).child) {
            if (node_map.count(child.first) > 0)
                node.add_child(node_map.at(child.first));
        }
    }
    return ret;
}

dycfg cut_ret_and_link_next(const dycfg& cfg) {
    dycfg cut_cfg;
    for (auto itr: cfg) {
        cut_cfg[itr.first] = itr.second;
        auto &node = cut_cfg.at(itr.first);
        if (node.is_ret) { // func return
            node.child.clear(); // cut the edge
        }
        if (node.is_call && !node.is_tail_call) { // func call
            address key(itr.first.first, itr.second.call_return_addr);
            if (cfg.count(key) > 0) {
                // link the edge with next inst if the next inst will be executed
                node.child[key] = node.count;
            }
        }
    }
    return cut_cfg;
}

dycfg cut_func_call_and_link(const dycfg& cfg) {
    dycfg cut_cfg;
    for (auto itr: cfg) {
        cut_cfg[itr.first] = itr.second;
        auto &node = cut_cfg.at(itr.first);
        if (!node.is_call && !node.is_ret) continue;
        node.child.clear(); // cut the edge
        if (node.is_ret || node.is_tail_call) continue;
        address key(itr.first.first,itr.second.call_return_addr);
        if (cfg.count(key) > 0) // inst after func call exists
            node.child[key] = node.count; // link nodes before and after the func call
    }
    return cut_cfg;
}

void extract_loops_and_nesting(dycfg& cfg, const address &cfg_entry, list<loop>& all_loops) {
    const graph_id size = cfg.size();
    // cut edge from ret inst to its successor
    const auto cut_ret_result = create_graph(cut_ret_and_link_next(cfg), cfg);
    const auto &cut_ret = cut_ret_result.first;
    const auto &graph_map = cut_ret_result.second;
    const auto entry = graph_map.at(cfg_entry);
    // cut edges from ret and call instructions
    const auto &cut_call = create_graph(cut_func_call_and_link(cfg), cfg).first;
    // do dfs from entry node
    const auto reachable_from_entry = DFS(entry, GRAPH_INVALID, cut_ret);

    vector<list<pair<graph_id, graph_id>>> back_edges;
    back_edges.resize(size);
    // 2d-array of dominances -> if (dominates[x][y]) then node x dominates node y
    vector<vector<bool>> dominates;
    dominates.resize(size);
    for (auto &itr: dominates) itr.resize(size);
    // for each node id, find all nodes that are dominated by id
#ifndef SERIAL
#pragma omp parallel for
#endif
    for (graph_id id = 0; id < size; id++) {
        if (!reachable_from_entry.at(id)) continue;
        // remove id and do dfs from entry node
        const auto reachable_without_id = DFS(entry, id, cut_ret);
        // do dfs from id but without calls
        const auto reachable_without_call = DFS(id, GRAPH_INVALID, cut_call);
        for (graph_id sub_id = 0; sub_id < size; sub_id++) {
            // node should be reachable
            if (!reachable_from_entry.at(sub_id)) continue;
            // it should not be reachable without going through id (id dominates sub_id).
            if (id != entry && reachable_without_id.at(sub_id)) continue;
            dominates.at(id).at(sub_id) = true;
            // check it's still reachable without calls (no cross-function loops).
            if (!reachable_without_call.at(sub_id)) continue;
            // check if sub_id have an edge to its dominator
            const auto &sub_node = cut_ret.at(sub_id);
            // check it's not recursion
            if (sub_node.is_call) continue;
            for (auto child : sub_node) {
                if (child == id) { // back edge exists
                    back_edges.at(id).emplace_back(id, sub_id);
                }
            }
        }
    }

    // compute dominance tree
#ifndef SERIAL
#pragma omp parallel for
#endif
    for (graph_id id = 0; id < size; id++) {
        if (!reachable_from_entry.at(id)) continue;
        graph_id candidate = GRAPH_INVALID;
        for (graph_id parent = 0; parent < size; parent++) {
            if (id == parent) continue;
            if (!dominates.at(parent).at(id)) continue;
            if (candidate == GRAPH_INVALID || dominates.at(candidate).at(parent)) {
                candidate = parent;
                continue;
            }
        }
        if (candidate == GRAPH_INVALID) continue;
        cut_ret.at(id).node->immediate_dominator = cut_ret.at(candidate).addr;
    }

    // find loops
    const auto cut_call_rev = reverse_graph(cut_call);

    for (size_t i = 0; i < back_edges.size(); i++) {
        for (auto itr : back_edges.at(i)) {
            loop tmp{};
            tmp.addr.head = cut_call_rev.at(itr.first).addr;
            tmp.addr.tail = cut_call_rev.at(itr.second).addr;
            if (itr.first != itr.second) { // loop has multiple blocks
                const auto body = DFS(itr.second, itr.first, cut_call_rev);
                graph_id id(-1);
                for (bool reachable: body) {
                    id++;
                    if (!reachable) continue;
                    tmp.loop_body.insert(cut_call_rev.at(id).addr);
                }
            }
            tmp.loop_body.insert(tmp.addr.head);
            tmp.back_edges.insert(tmp.addr.tail);
            all_loops.push_back(tmp);
        }
    }
}
