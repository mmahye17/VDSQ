# AVL_Tree.py
class AVLNode:
    def __init__(self, plaintext=None, ciphertext=None, index=None, number=None):
        self.plaintext = plaintext  # 存储明文（浮点数，支持小数点后10位）
        self.ciphertext = ciphertext  # 存储密文 (left_components, right_components)
        self.index = index  # 存储原始数据集下标或 Cantor pairing 结果
        self.number = number  # 树索引号
        self.left = None
        self.right = None
        self.height = 1

class AVLTree:
    def __init__(self, ore_instance=None):
        self.root = None
        self.ore = ore_instance  # 用于比较密文和加密

    def height(self, node):
        if not node:
            return 0
        return node.height

    def balance_factor(self, node):
        if not node:
            return 0
        return self.height(node.left) - self.height(node.right)

    def update_height(self, node):
        if not node:
            return
        node.height = max(self.height(node.left), self.height(node.right)) + 1

    def right_rotate(self, y):
        x = y.left
        T2 = x.right
        x.right = y
        y.left = T2
        self.update_height(y)
        self.update_height(x)
        return x

    def left_rotate(self, x):
        y = x.right
        T2 = y.left
        y.left = x
        x.right = T2
        self.update_height(x)
        self.update_height(y)
        return y

    def insert(self, root, plaintext=None, ciphertext=None, index=None):
        from ore import compare, encrypt
        if not root:
            return AVLNode(plaintext, ciphertext, index=index)
        if ciphertext and root.ciphertext:
            cmp = compare(ciphertext, root.ciphertext, self.ore)
        else:
            cmp = -1 if plaintext < root.plaintext else (1 if plaintext > root.plaintext else 0)
        if cmp < 0:
            root.left = self.insert(root.left, plaintext, ciphertext, index=index)
        elif cmp > 0:
            root.right = self.insert(root.right, plaintext, ciphertext, index=index)
        else:
            return root
        self.update_height(root)
        balance = self.balance_factor(root)
        if balance > 1:
            if (ciphertext and compare(ciphertext, root.left.ciphertext, self.ore) < 0) or \
               (plaintext is not None and plaintext < root.left.plaintext):
                return self.right_rotate(root)
        if balance < -1:
            if (ciphertext and compare(ciphertext, root.right.ciphertext, self.ore) > 0) or \
               (plaintext is not None and plaintext > root.right.plaintext):
                return self.left_rotate(root)
        if balance > 1:
            if (ciphertext and compare(ciphertext, root.left.ciphertext, self.ore) > 0) or \
               (plaintext is not None and plaintext > root.left.plaintext):
                root.left = self.left_rotate(root.left)
                return self.right_rotate(root)
        if balance < -1:
            if (ciphertext and compare(ciphertext, root.right.ciphertext, self.ore) < 0) or \
               (plaintext is not None and plaintext < root.right.plaintext):
                root.right = self.right_rotate(root.right)
                return self.left_rotate(root)
        return root

    def insert_plaintext(self, plaintext, index=None):
        """插入明文，index 为原始数据集下标"""
        self.root = self.insert(self.root, plaintext=plaintext, index=index)

    def insert_ciphertext(self, ciphertext, index=None):
        """插入密文并支持可选的 index"""
        self.root = self.insert(self.root, ciphertext=ciphertext, index=index)

    def encrypt_plaintexts(self):
        """遍历树并对明文加密"""
        from ore import encrypt
        def _encrypt_node(node):
            if not node:
                return
            if node.plaintext is not None and node.ciphertext is None:
                node.ciphertext = encrypt(str(node.plaintext), self.ore)
            _encrypt_node(node.left)
            _encrypt_node(node.right)
        _encrypt_node(self.root)

    def clear_plaintexts(self):
        """遍历树并清除明文"""
        def _clear_node(node):
            if not node:
                return
            node.plaintext = None
            _clear_node(node.left)
            _clear_node(node.right)
        _clear_node(self.root)

    def assign_indices(self):
        """保留插入时提供的 index（原始数据集下标），不重新赋值"""
        pass  # 不再重新赋值索引，保留插入时的 index

    def _inorder_traversal(self, node, result=None):
        """中序遍历并收集节点信息"""
        if result is None:
            result = []
        if node:
            self._inorder_traversal(node.left, result)
            plaintext_str = f"{node.plaintext:.10f}" if node.plaintext is not None else "None"
            ciphertext_str = (node.ciphertext[0][0][0][:10] + "..."
                             if node.ciphertext and isinstance(node.ciphertext[0][0], tuple) and len(node.ciphertext[0][0]) > 0
                             else "None")
            index_str = str(node.index) if node.index is not None else "None"
            number_str = str(node.number) if node.number is not None else "None"
            result.append(f"Plaintext: {plaintext_str}, Ciphertext: {ciphertext_str}, Index: {index_str}, Number: {number_str}")
            self._inorder_traversal(node.right, result)
        return result

    def print_tree(self, max_nodes=10):
        """打印树的内容"""
        nodes = self._inorder_traversal(self.root)
        total_nodes = len(nodes)
        tree_height = self.height(self.root)
        print(f"\nAVL Tree Contents (Inorder Traversal):")
        print(f"  Tree Height: {tree_height}")
        print(f"  Total Nodes: {total_nodes}")
        if total_nodes > max_nodes:
            half = max_nodes // 2
            print(f"  Nodes (showing first {half} and last {half} of {total_nodes} total):")
            print("    First:", nodes[:half])
            print("    Last:", nodes[-half:])
        else:
            print("  Nodes:", nodes)