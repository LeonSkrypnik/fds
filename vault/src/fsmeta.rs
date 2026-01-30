use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeType {
    Dir,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub index: u32,
    pub offset: u64,
    pub len: u32,
    pub nonce: [u8; 12],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: u64,
    pub parent_id: u64,
    pub node_type: NodeType,
    pub name: String,

    // file only
    pub size: u64,
    pub chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeRange {
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub next_id: u64,
    pub root_id: u64,
    pub nodes: Vec<Node>,
    pub freelist: Vec<FreeRange>,
}

impl Metadata {
    pub fn new_empty() -> Self {
        let root = Node {
            id: 1,
            parent_id: 0,
            node_type: NodeType::Dir,
            name: "/".to_string(),
            size: 0,
            chunks: vec![],
        };
        Self {
            next_id: 2,
            root_id: 1,
            nodes: vec![root],
            freelist: vec![],
        }
    }

    pub fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn get_node(&self, id: u64) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn get_node_mut(&mut self, id: u64) -> Option<&mut Node> {
        self.nodes.iter_mut().find(|n| n.id == id)
    }

    pub fn children_of(&self, parent_id: u64) -> Vec<&Node> {
        let mut v: Vec<&Node> = self.nodes.iter().filter(|n| n.parent_id == parent_id).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn mkdir(&mut self, parent_id: u64, name: String) -> anyhow::Result<u64> {
        if self.get_node(parent_id).filter(|n| n.node_type == NodeType::Dir).is_none() {
            anyhow::bail!("parent is not a directory");
        }
        if self
            .nodes
            .iter()
            .any(|n| n.parent_id == parent_id && n.name == name)
        {
            anyhow::bail!("name already exists");
        }
        let id = self.alloc_id();
        self.nodes.push(Node {
            id,
            parent_id,
            node_type: NodeType::Dir,
            name,
            size: 0,
            chunks: vec![],
        });
        Ok(id)
    }

    pub fn add_file(
        &mut self,
        parent_id: u64,
        name: String,
        size: u64,
        chunks: Vec<ChunkRef>,
    ) -> anyhow::Result<u64> {
        if self.get_node(parent_id).filter(|n| n.node_type == NodeType::Dir).is_none() {
            anyhow::bail!("parent is not a directory");
        }
        if self
            .nodes
            .iter()
            .any(|n| n.parent_id == parent_id && n.name == name)
        {
            anyhow::bail!("name already exists");
        }
        let id = self.alloc_id();
        self.nodes.push(Node {
            id,
            parent_id,
            node_type: NodeType::File,
            name,
            size,
            chunks,
        });
        Ok(id)
    }

    pub fn rename(&mut self, id: u64, new_name: String) -> anyhow::Result<()> {
        let parent_id = self.get_node(id).ok_or_else(|| anyhow::anyhow!("not found"))?.parent_id;
        if self
            .nodes
            .iter()
            .any(|n| n.parent_id == parent_id && n.name == new_name)
        {
            anyhow::bail!("name already exists");
        }
        let n = self.get_node_mut(id).ok_or_else(|| anyhow::anyhow!("not found"))?;
        n.name = new_name;
        Ok(())
    }

    pub fn remove_subtree(&mut self, id: u64) -> anyhow::Result<()> {
        if id == self.root_id {
            anyhow::bail!("cannot remove root");
        }
        if self.get_node(id).is_none() {
            anyhow::bail!("not found");
        }

        // Collect ids in subtree.
        let mut stack = vec![id];
        let mut to_remove: Vec<u64> = vec![];
        while let Some(cur) = stack.pop() {
            to_remove.push(cur);
            for ch in self.nodes.iter().filter(|n| n.parent_id == cur) {
                stack.push(ch.id);
            }
        }

        self.nodes.retain(|n| !to_remove.contains(&n.id));
        Ok(())
    }
}