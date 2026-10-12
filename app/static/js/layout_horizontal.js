// Left-to-right network layout (like the Omada topology view): the top-level device is on the left, every
// level is a column to its right, and the children of a device are stacked next to it. Many leaf devices
// (clients) are folded into a grid and can be collapsed. Pure functions, no DOM.

export const GRID = {
  colW: 280, // distance between levels
  leafColW: 230, // distance between the columns of a leaf grid
  rowH: 58, // distance between rows
  leafRows: 8, // a grid gets another column after this many rows
  collapseOver: 8, // leaf children above this count start collapsed
  groupGap: 18, // extra space between top-level trees
};

export function buildTree(nodes) {
  const ids = new Set(nodes.map((n) => n.id));
  const children = new Map(nodes.map((n) => [n.id, []]));
  const roots = [];
  for (const n of nodes) {
    if (n.parent_id != null && n.parent_id !== n.id && ids.has(n.parent_id)) children.get(n.parent_id).push(n.id);
    else roots.push(n.id);
  }
  const order = new Map(nodes.map((n, i) => [n.id, i]));
  const byOrder = (a, b) => order.get(a) - order.get(b);
  for (const list of children.values()) list.sort(byOrder);
  return { children, roots: roots.sort(byOrder) };
}

export function leafIds(tree, parentId) {
  return (tree.children.get(parentId) || []).filter((c) => tree.children.get(c).length === 0);
}

// Parents whose leaf children are folded away unless the user opened them.
export function defaultCollapsed(tree, threshold = GRID.collapseOver) {
  const out = new Set();
  for (const id of tree.children.keys()) if (leafIds(tree, id).length > threshold) out.add(id);
  return out;
}

// nodes: [{id, parent_id}], collapsed: Set of parent ids whose leaf children are hidden.
// Returns {positions: Map id -> {x, y}, hidden: Set of folded ids, folded: Map parent id -> hidden leaf count}.
export function layoutHorizontal(nodes, collapsed = new Set()) {
  const tree = buildTree(nodes);
  const positions = new Map();
  const hidden = new Set();
  const folded = new Map();
  const seen = new Set();

  // places the subtree of `id` starting at row position `top`; returns the y below the subtree
  function place(id, depth, top) {
    seen.add(id);
    const kids = tree.children.get(id).filter((c) => !seen.has(c));
    const leaves = kids.filter((c) => tree.children.get(c).length === 0);
    const inner = kids.filter((c) => tree.children.get(c).length > 0);
    const x = depth * GRID.colW;
    if (kids.length === 0) {
      positions.set(id, { x, y: top + GRID.rowH / 2 });
      return top + GRID.rowH;
    }
    const ys = [];
    let y = top;
    for (const child of inner) {
      const bottom = place(child, depth + 1, y);
      ys.push(positions.get(child).y);
      y = bottom;
    }
    if (collapsed.has(id) && leaves.length > 0) {
      for (const leaf of leaves) {
        seen.add(leaf);
        hidden.add(leaf);
      }
      folded.set(id, leaves.length);
    } else if (leaves.length > 0) {
      const cols = Math.ceil(leaves.length / GRID.leafRows);
      const rows = Math.ceil(leaves.length / cols);
      leaves.forEach((leaf, i) => {
        seen.add(leaf);
        positions.set(leaf, { x: (depth + 1) * GRID.colW + (i % cols) * GRID.leafColW, y: y + Math.floor(i / cols) * GRID.rowH + GRID.rowH / 2 });
      });
      ys.push(y + GRID.rowH / 2, y + (rows - 1) * GRID.rowH + GRID.rowH / 2);
      y += rows * GRID.rowH;
    }
    if (ys.length === 0) {
      positions.set(id, { x, y: top + GRID.rowH / 2 });
      return top + GRID.rowH;
    }
    positions.set(id, { x, y: (Math.min(...ys) + Math.max(...ys)) / 2 });
    return Math.max(y, top + GRID.rowH);
  }

  // big trees first, single devices last
  const size = (id) => 1 + tree.children.get(id).reduce((sum, c) => sum + size(c), 0);
  const roots = [...tree.roots].sort((a, b) => size(b) - size(a) || tree.roots.indexOf(a) - tree.roots.indexOf(b));
  let top = 0;
  for (const root of roots) {
    if (seen.has(root)) continue;
    top = place(root, 0, top) + GRID.groupGap;
  }
  for (const n of nodes) if (!positions.has(n.id) && !hidden.has(n.id)) positions.set(n.id, { x: 0, y: (top += GRID.rowH) }); // safety net
  return { positions, hidden, folded };
}

// Top-to-bottom variant of the same layout: the top-level device is at the top, every level is a row below it, and the
// children of a device sit side by side under it. Client devices are folded into a block under their switch or access point.
export const GRID_V = {
  rowH: 130, // distance between levels
  colW: 210, // width of a card slot (cards are at most 190 wide)
  leafRowH: 74, // distance between the rows of a leaf block
  leafCols: 6, // a leaf block gets another row after this many devices
  groupGap: 40, // extra space between top-level trees
};

// Same arguments and result as layoutHorizontal.
export function layoutVertical(nodes, collapsed = new Set()) {
  const tree = buildTree(nodes);
  const positions = new Map();
  const hidden = new Set();
  const folded = new Map();
  const seen = new Set();

  // places the subtree of `id` starting at horizontal position `left`; returns the x right of the subtree
  function place(id, depth, left) {
    seen.add(id);
    const kids = tree.children.get(id).filter((c) => !seen.has(c));
    const leaves = kids.filter((c) => tree.children.get(c).length === 0);
    const inner = kids.filter((c) => tree.children.get(c).length > 0);
    const y = depth * GRID_V.rowH;
    if (kids.length === 0) {
      positions.set(id, { x: left + GRID_V.colW / 2, y });
      return left + GRID_V.colW;
    }
    const xs = [];
    let x = left;
    for (const child of inner) {
      const right = place(child, depth + 1, x);
      xs.push(positions.get(child).x);
      x = right;
    }
    if (collapsed.has(id) && leaves.length > 0) {
      for (const leaf of leaves) {
        seen.add(leaf);
        hidden.add(leaf);
      }
      folded.set(id, leaves.length);
    } else if (leaves.length > 0) {
      const rows = Math.ceil(leaves.length / GRID_V.leafCols);
      const cols = Math.ceil(leaves.length / rows);
      leaves.forEach((leaf, i) => {
        seen.add(leaf);
        positions.set(leaf, { x: x + (i % cols) * GRID_V.colW + GRID_V.colW / 2, y: (depth + 1) * GRID_V.rowH + Math.floor(i / cols) * GRID_V.leafRowH });
      });
      xs.push(x + GRID_V.colW / 2, x + (cols - 1) * GRID_V.colW + GRID_V.colW / 2);
      x += cols * GRID_V.colW;
    }
    if (xs.length === 0) {
      positions.set(id, { x: left + GRID_V.colW / 2, y });
      return left + GRID_V.colW;
    }
    positions.set(id, { x: (Math.min(...xs) + Math.max(...xs)) / 2, y });
    return Math.max(x, left + GRID_V.colW);
  }

  // big trees first, single devices last
  const size = (id) => 1 + tree.children.get(id).reduce((sum, c) => sum + size(c), 0);
  const roots = [...tree.roots].sort((a, b) => size(b) - size(a) || tree.roots.indexOf(a) - tree.roots.indexOf(b));
  let left = 0;
  for (const root of roots) {
    if (seen.has(root)) continue;
    left = place(root, 0, left) + GRID_V.groupGap;
  }
  for (const n of nodes) if (!positions.has(n.id) && !hidden.has(n.id)) positions.set(n.id, { x: (left += GRID_V.colW), y: 0 }); // safety net
  return { positions, hidden, folded };
}
