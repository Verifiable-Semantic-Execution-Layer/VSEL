//! Proof obligation dependency graph.
//!
//! Implements the dependency graph tracking from Requirement 16.7:
//!   AX → DEF → LEM → SAFE → LIVE → COMP → ECON → CONST → PROOF
//!
//! Key invariant: **unresolved nodes make downstream obligations suspect**.
//! If an axiom is unresolved, every lemma, safety property, and proof
//! obligation that transitively depends on it is marked suspect.
//!
//! Requirements: 16.7

use std::collections::{BTreeMap, BTreeSet};

use crate::obligations::{ObligationStatus, ObligationTracker};

// ---------------------------------------------------------------------------
// Node status in the dependency graph
// ---------------------------------------------------------------------------

/// Status of a node in the dependency graph, accounting for upstream health.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeHealth {
    /// All upstream dependencies are discharged and this node is discharged.
    Healthy,
    /// This node is discharged but at least one upstream dependency is not.
    Suspect,
    /// This node is not yet discharged (unresolved or in-progress).
    Unresolved,
    /// This node or an upstream dependency has failed.
    Failed,
}

impl std::fmt::Display for NodeHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeHealth::Healthy => write!(f, "Healthy"),
            NodeHealth::Suspect => write!(f, "Suspect"),
            NodeHealth::Unresolved => write!(f, "Unresolved"),
            NodeHealth::Failed => write!(f, "Failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Dependency graph
// ---------------------------------------------------------------------------

/// Dependency graph for proof obligations.
///
/// Tracks directed edges from upstream (dependency) to downstream (dependent).
/// Computes transitive health: unresolved or failed upstream nodes propagate
/// suspect/failed status downstream.
///
/// Requirement 16.7
#[derive(Clone, Debug)]
pub struct DependencyGraph {
    /// Adjacency list: node → set of nodes it depends on (upstream).
    upstream: BTreeMap<String, BTreeSet<String>>,
    /// Reverse adjacency: node → set of nodes that depend on it (downstream).
    downstream: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyGraph {
    /// Create a new empty dependency graph.
    pub fn new() -> Self {
        Self {
            upstream: BTreeMap::new(),
            downstream: BTreeMap::new(),
        }
    }

    /// Build a dependency graph from the obligation tracker.
    ///
    /// Extracts the dependency edges from each tracked obligation.
    pub fn from_tracker(tracker: &ObligationTracker) -> Self {
        let mut graph = Self::new();

        for obl in tracker.all() {
            // Ensure the node exists even if it has no dependencies.
            graph.upstream.entry(obl.obligation_id.clone()).or_default();
            graph
                .downstream
                .entry(obl.obligation_id.clone())
                .or_default();

            for dep in &obl.dependencies {
                graph.add_edge(dep, &obl.obligation_id);
            }
        }

        graph
    }

    /// Add a directed dependency edge: `dependent` depends on `dependency`.
    pub fn add_edge(&mut self, dependency: &str, dependent: &str) {
        self.upstream
            .entry(dependent.to_string())
            .or_default()
            .insert(dependency.to_string());
        self.downstream
            .entry(dependency.to_string())
            .or_default()
            .insert(dependent.to_string());
        // Ensure both nodes exist in both maps.
        self.upstream.entry(dependency.to_string()).or_default();
        self.downstream.entry(dependent.to_string()).or_default();
    }

    /// Get the direct upstream dependencies of a node.
    pub fn dependencies_of(&self, node: &str) -> Vec<&str> {
        self.upstream
            .get(node)
            .map(|deps| deps.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get the direct downstream dependents of a node.
    pub fn dependents_of(&self, node: &str) -> Vec<&str> {
        self.downstream
            .get(node)
            .map(|deps| deps.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get all transitive upstream dependencies of a node (recursive).
    pub fn transitive_dependencies(&self, node: &str) -> BTreeSet<String> {
        let mut visited = BTreeSet::new();
        self.collect_upstream(node, &mut visited);
        visited.remove(node);
        visited
    }

    /// Get all transitive downstream dependents of a node (recursive).
    pub fn transitive_dependents(&self, node: &str) -> BTreeSet<String> {
        let mut visited = BTreeSet::new();
        self.collect_downstream(node, &mut visited);
        visited.remove(node);
        visited
    }

    /// All node IDs in the graph.
    pub fn nodes(&self) -> Vec<&str> {
        self.upstream.keys().map(|s| s.as_str()).collect()
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.upstream.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.upstream.values().map(|deps| deps.len()).sum()
    }

    /// Get root nodes (no upstream dependencies).
    pub fn roots(&self) -> Vec<&str> {
        self.upstream
            .iter()
            .filter(|(_, deps)| deps.is_empty())
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Get leaf nodes (no downstream dependents).
    pub fn leaves(&self) -> Vec<&str> {
        self.downstream
            .iter()
            .filter(|(_, deps)| deps.is_empty())
            .map(|(id, _)| id.as_str())
            .collect()
    }

    // -----------------------------------------------------------------------
    // Health computation
    // -----------------------------------------------------------------------

    /// Compute the health of every node in the graph.
    ///
    /// Requirement 16.7: unresolved nodes make downstream suspect.
    ///
    /// Algorithm:
    /// 1. For each node, check its own status from the tracker.
    /// 2. For each node, check all transitive upstream dependencies.
    /// 3. If any upstream is Failed → this node is Failed (if not already).
    /// 4. If any upstream is Unresolved/InProgress → this node is Suspect
    ///    (even if this node itself is Discharged).
    /// 5. If all upstream are Discharged and this node is Discharged → Healthy.
    pub fn compute_health(&self, tracker: &ObligationTracker) -> BTreeMap<String, NodeHealth> {
        let mut health = BTreeMap::new();

        for node_id in self.upstream.keys() {
            let node_health = self.compute_node_health(node_id, tracker);
            health.insert(node_id.clone(), node_health);
        }

        health
    }

    /// Compute health for a single node.
    pub fn compute_node_health(&self, node_id: &str, tracker: &ObligationTracker) -> NodeHealth {
        let own_status = tracker
            .get(node_id)
            .map(|o| o.status)
            .unwrap_or(ObligationStatus::Unresolved);

        // If this node itself has failed, it's Failed regardless of upstream.
        if own_status == ObligationStatus::Failed {
            return NodeHealth::Failed;
        }

        // Check all transitive upstream dependencies.
        let upstream = self.transitive_dependencies(node_id);
        let mut any_upstream_failed = false;
        let mut any_upstream_unresolved = false;

        for dep_id in &upstream {
            if let Some(dep) = tracker.get(dep_id) {
                match dep.status {
                    ObligationStatus::Failed => {
                        any_upstream_failed = true;
                    }
                    ObligationStatus::Unresolved | ObligationStatus::InProgress => {
                        any_upstream_unresolved = true;
                    }
                    ObligationStatus::Discharged => {}
                }
            }
        }

        if any_upstream_failed {
            return NodeHealth::Failed;
        }

        if own_status == ObligationStatus::Discharged {
            if any_upstream_unresolved {
                NodeHealth::Suspect
            } else {
                NodeHealth::Healthy
            }
        } else {
            // Own status is Unresolved or InProgress.
            NodeHealth::Unresolved
        }
    }

    /// Get all suspect nodes — discharged but with unresolved upstream.
    pub fn suspect_nodes(&self, tracker: &ObligationTracker) -> Vec<String> {
        let health = self.compute_health(tracker);
        health
            .into_iter()
            .filter(|(_, h)| *h == NodeHealth::Suspect)
            .map(|(id, _)| id)
            .collect()
    }

    /// Get a health summary.
    pub fn health_summary(&self, tracker: &ObligationTracker) -> HealthSummary {
        let health = self.compute_health(tracker);
        let mut summary = HealthSummary::default();
        summary.total = health.len();

        for h in health.values() {
            match h {
                NodeHealth::Healthy => summary.healthy += 1,
                NodeHealth::Suspect => summary.suspect += 1,
                NodeHealth::Unresolved => summary.unresolved += 1,
                NodeHealth::Failed => summary.failed += 1,
            }
        }

        summary
    }

    /// Detect cycles in the dependency graph.
    ///
    /// Returns `true` if the graph is acyclic (valid).
    pub fn is_acyclic(&self) -> bool {
        // Kahn's algorithm for topological sort.
        let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
        for (node, deps) in &self.upstream {
            in_degree.entry(node.as_str()).or_insert(0);
            // in_degree is the number of upstream deps.
            *in_degree.entry(node.as_str()).or_insert(0) = deps.len();
        }

        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&node, _)| node)
            .collect();

        let mut visited = 0;

        while let Some(node) = queue.pop() {
            visited += 1;
            if let Some(dependents) = self.downstream.get(node) {
                for dep in dependents {
                    if let Some(deg) = in_degree.get_mut(dep.as_str()) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(dep.as_str());
                        }
                    }
                }
            }
        }

        visited == self.upstream.len()
    }

    /// Topological sort of the graph (returns None if cyclic).
    pub fn topological_sort(&self) -> Option<Vec<String>> {
        let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
        for (node, deps) in &self.upstream {
            in_degree.entry(node.as_str()).or_insert(0);
            *in_degree.entry(node.as_str()).or_insert(0) = deps.len();
        }

        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&node, _)| node)
            .collect();
        queue.sort(); // Deterministic ordering.

        let mut result = Vec::new();

        while let Some(node) = queue.pop() {
            result.push(node.to_string());
            if let Some(dependents) = self.downstream.get(node) {
                let mut next_batch = Vec::new();
                for dep in dependents {
                    if let Some(deg) = in_degree.get_mut(dep.as_str()) {
                        *deg -= 1;
                        if *deg == 0 {
                            next_batch.push(dep.as_str());
                        }
                    }
                }
                next_batch.sort();
                // Push in reverse so we pop in sorted order.
                for n in next_batch.into_iter().rev() {
                    queue.push(n);
                }
            }
        }

        if result.len() == self.upstream.len() {
            Some(result)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn collect_upstream(&self, node: &str, visited: &mut BTreeSet<String>) {
        if !visited.insert(node.to_string()) {
            return; // Already visited — prevent infinite loops on cycles.
        }
        if let Some(deps) = self.upstream.get(node) {
            for dep in deps {
                self.collect_upstream(dep, visited);
            }
        }
    }

    fn collect_downstream(&self, node: &str, visited: &mut BTreeSet<String>) {
        if !visited.insert(node.to_string()) {
            return;
        }
        if let Some(deps) = self.downstream.get(node) {
            for dep in deps {
                self.collect_downstream(dep, visited);
            }
        }
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Health summary
// ---------------------------------------------------------------------------

/// Summary of dependency graph health.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HealthSummary {
    pub total: usize,
    pub healthy: usize,
    pub suspect: usize,
    pub unresolved: usize,
    pub failed: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obligations::build_obligation_tracker;
    use crate::registry::build_traceability_matrix;

    fn build_full_graph() -> (ObligationTracker, DependencyGraph) {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);
        let graph = DependencyGraph::from_tracker(&tracker);
        (tracker, graph)
    }

    #[test]
    fn test_graph_has_all_46_nodes() {
        let (_, graph) = build_full_graph();
        assert_eq!(graph.node_count(), 46);
    }

    #[test]
    fn test_graph_is_acyclic() {
        let (_, graph) = build_full_graph();
        assert!(graph.is_acyclic(), "Dependency graph must be acyclic");
    }

    #[test]
    fn test_topological_sort_succeeds() {
        let (_, graph) = build_full_graph();
        let sorted = graph.topological_sort();
        assert!(
            sorted.is_some(),
            "Topological sort should succeed for acyclic graph"
        );
        let sorted = sorted.unwrap();
        assert_eq!(sorted.len(), 46);
    }

    #[test]
    fn test_axioms_are_roots() {
        let (_, graph) = build_full_graph();
        let roots = graph.roots();

        // All AX-1..AX-6 should be roots (no upstream dependencies).
        for i in 1..=6 {
            let id = format!("AX-{}", i);
            assert!(
                roots.contains(&id.as_str()),
                "AX-{} should be a root node",
                i
            );
        }
    }

    #[test]
    fn test_all_unresolved_means_all_unresolved_health() {
        let (tracker, graph) = build_full_graph();
        let health = graph.compute_health(&tracker);

        for (id, h) in &health {
            assert_eq!(
                *h,
                NodeHealth::Unresolved,
                "Node '{}' should be Unresolved when nothing is discharged",
                id
            );
        }
    }

    #[test]
    fn test_discharged_axiom_with_unresolved_downstream() {
        let (mut tracker, graph) = build_full_graph();

        // Discharge AX-1.
        tracker
            .discharge("AX-1", "evidence", "2025-01-15", "alice")
            .unwrap();

        let health = graph.compute_health(&tracker);

        // AX-1 itself: all its upstream (none) are discharged, and it's discharged → Healthy.
        // But wait — AX-1 has no upstream, so it should be Healthy.
        // However, other AX nodes that AX-1 doesn't depend on are still unresolved.
        // AX-1's health depends only on its own status and its upstream.
        assert_eq!(health["AX-1"], NodeHealth::Healthy);

        // LEM-1 depends on AX-1 and AX-2. AX-2 is unresolved → LEM-1 is Unresolved (own status).
        assert_eq!(health["LEM-1"], NodeHealth::Unresolved);
    }

    #[test]
    fn test_suspect_propagation() {
        let (mut tracker, graph) = build_full_graph();

        // Discharge AX-1, AX-2, and LEM-1.
        // LEM-1 depends on AX-1 and AX-2, so if both are discharged, LEM-1 is Healthy.
        tracker.discharge("AX-1", "e", "d", "r").unwrap();
        tracker.discharge("AX-2", "e", "d", "r").unwrap();
        tracker.discharge("LEM-1", "e", "d", "r").unwrap();

        let health = graph.compute_health(&tracker);
        assert_eq!(health["LEM-1"], NodeHealth::Healthy);

        // Now reset AX-1 to unresolved — LEM-1 should become Suspect.
        tracker.reset("AX-1").unwrap();
        let health = graph.compute_health(&tracker);
        assert_eq!(health["LEM-1"], NodeHealth::Suspect);

        // SAFE-1 depends on LEM-1 and LEM-2. LEM-1 is Suspect (discharged but upstream unresolved).
        // SAFE-1 itself is Unresolved (not discharged).
        assert_eq!(health["SAFE-1"], NodeHealth::Unresolved);
    }

    #[test]
    fn test_failed_propagation() {
        let (mut tracker, graph) = build_full_graph();

        // Discharge AX-1, then mark it failed.
        tracker
            .mark_failed("AX-1", "failure evidence", "2025-01-15", "alice")
            .unwrap();

        let health = graph.compute_health(&tracker);
        assert_eq!(health["AX-1"], NodeHealth::Failed);

        // Discharge LEM-1 (depends on AX-1 and AX-2).
        // Even though LEM-1 is discharged, AX-1 is failed → LEM-1 is Failed.
        tracker.discharge("AX-2", "e", "d", "r").unwrap();
        tracker.discharge("LEM-1", "e", "d", "r").unwrap();

        let health = graph.compute_health(&tracker);
        assert_eq!(health["LEM-1"], NodeHealth::Failed);
    }

    #[test]
    fn test_all_discharged_means_all_healthy() {
        let (mut tracker, graph) = build_full_graph();

        // Discharge everything in topological order.
        let sorted = graph.topological_sort().unwrap();
        for id in &sorted {
            tracker
                .discharge(id, "evidence", "2025-01-15", "reviewer")
                .unwrap();
        }

        let health = graph.compute_health(&tracker);
        for (id, h) in &health {
            assert_eq!(
                *h,
                NodeHealth::Healthy,
                "Node '{}' should be Healthy when all are discharged",
                id
            );
        }

        let summary = graph.health_summary(&tracker);
        assert_eq!(summary.healthy, 46);
        assert_eq!(summary.suspect, 0);
        assert_eq!(summary.unresolved, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_suspect_nodes_query() {
        let (mut tracker, graph) = build_full_graph();

        // Discharge AX-2 and LEM-1 but leave AX-1 unresolved.
        // LEM-1 depends on AX-1 (unresolved) and AX-2 (discharged).
        // LEM-1 is discharged but upstream AX-1 is unresolved → Suspect.
        tracker.discharge("AX-2", "e", "d", "r").unwrap();
        tracker.discharge("LEM-1", "e", "d", "r").unwrap();

        let suspects = graph.suspect_nodes(&tracker);
        assert!(suspects.contains(&"LEM-1".to_string()));
    }

    #[test]
    fn test_transitive_dependencies() {
        let (_, graph) = build_full_graph();

        // SAFE-1 depends on LEM-1 and LEM-2.
        // LEM-1 depends on AX-1 and AX-2.
        // LEM-2 depends on LEM-1 and AX-3.
        // So transitive deps of SAFE-1 include: LEM-1, LEM-2, AX-1, AX-2, AX-3.
        let deps = graph.transitive_dependencies("SAFE-1");
        assert!(deps.contains("LEM-1"));
        assert!(deps.contains("LEM-2"));
        assert!(deps.contains("AX-1"));
        assert!(deps.contains("AX-2"));
        assert!(deps.contains("AX-3"));
    }

    #[test]
    fn test_transitive_dependents() {
        let (_, graph) = build_full_graph();

        // AX-1 is a root. Its transitive dependents should include
        // many downstream obligations.
        let dependents = graph.transitive_dependents("AX-1");
        assert!(!dependents.is_empty());
        // LEM-1 depends on AX-1.
        assert!(dependents.contains("LEM-1"));
    }

    #[test]
    fn test_health_summary_initial() {
        let (tracker, graph) = build_full_graph();
        let summary = graph.health_summary(&tracker);

        assert_eq!(summary.total, 46);
        assert_eq!(summary.unresolved, 46);
        assert_eq!(summary.healthy, 0);
        assert_eq!(summary.suspect, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_direct_dependencies_and_dependents() {
        let (_, graph) = build_full_graph();

        // LEM-1 depends on AX-1 and AX-2.
        let deps = graph.dependencies_of("LEM-1");
        assert!(deps.contains(&"AX-1"));
        assert!(deps.contains(&"AX-2"));

        // AX-1 has downstream dependents including LEM-1.
        let dependents = graph.dependents_of("AX-1");
        assert!(dependents.contains(&"LEM-1"));
    }

    #[test]
    fn test_empty_graph() {
        let graph = DependencyGraph::new();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
        assert!(graph.is_acyclic());
        assert_eq!(graph.topological_sort(), Some(vec![]));
    }

    #[test]
    fn test_cycle_detection() {
        let mut graph = DependencyGraph::new();
        graph.add_edge("A", "B");
        graph.add_edge("B", "C");
        graph.add_edge("C", "A"); // Cycle!

        assert!(!graph.is_acyclic());
        assert!(graph.topological_sort().is_none());
    }
}
