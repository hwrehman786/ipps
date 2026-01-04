import threading

# ==========================================
# LAB 5 & 7: Doubly Linked List & Queue
# ==========================================
class DoublyNode:
    def __init__(self, data):
        self.data = data
        self.next = None
        self.prev = None

class DoublyLinkedListQueue:
    """Thread-safe Queue using a Doubly Linked List"""
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0
        self.lock = threading.Lock() # Necessary for threading

    def put(self, item):
        # Enqueue at Tail
        with self.lock:
            new_node = DoublyNode(item)
            if self.tail is None:
                self.head = new_node
                self.tail = new_node
            else:
                self.tail.next = new_node
                new_node.prev = self.tail
                self.tail = new_node
            self.size += 1

    def get(self):
        # Dequeue from Head
        with self.lock:
            if self.head is None:
                return None
            
            data = self.head.data
            self.head = self.head.next
            
            if self.head is None:
                self.tail = None
            else:
                self.head.prev = None
                
            self.size -= 1
            return data

    def empty(self):
        with self.lock:
            return self.head is None

# ==========================================
# LAB 12: Merge Sort Algorithm
# ==========================================
def merge_sort(packet_list):
    """Sorts list of packets by size (index 3) using Merge Sort"""
    if len(packet_list) <= 1:
        return packet_list

    mid = len(packet_list) // 2
    left_half = packet_list[:mid]
    right_half = packet_list[mid:]

    left_sorted = merge_sort(left_half)
    right_sorted = merge_sort(right_half)

    return merge(left_sorted, right_sorted)

def merge(left, right):
    sorted_list = []
    i = j = 0
    
    while i < len(left) and j < len(right):
        # Compare Packet Size (Index 3) descending
        if left[i][3] > right[j][3]: 
            sorted_list.append(left[i])
            i += 1
        else:
            sorted_list.append(right[j])
            j += 1
            
    sorted_list.extend(left[i:])
    sorted_list.extend(right[j:])
    return sorted_list

# ==========================================
# LAB 8: Binary Search Tree (Modified)
# ==========================================
class BSTNode:
    def __init__(self, ipaddress):
        self.ip = ipaddress
        self.left = None
        self.right = None

class BlacklistBST:
    def __init__(self):
        self.root = None

    def insert(self, ipaddress):
        if self.root is None:
            self.root = BSTNode(ipaddress)
        else:
            self.insertrecursive(self.root, ipaddress)

    def insertrecursive(self, node, ipaddress):
        if ipaddress < node.ip:
            if node.left is None:
                node.left = BSTNode(ipaddress)
            else:
                self.insertrecursive(node.left, ipaddress)
        elif ipaddress > node.ip:
            if node.right is None:
                node.right = BSTNode(ipaddress)
            else:
                self.insertrecursive(node.right, ipaddress)

    def search(self, ipaddress):
        return self.searchrecursive(self.root, ipaddress)

    def searchrecursive(self, node, ipaddress):
        if node is None: return False
        if ipaddress == node.ip: return True
        elif ipaddress < node.ip: return self.searchrecursive(node.left, ipaddress)
        else: return self.searchrecursive(node.right, ipaddress)

    def delete(self, ipaddress):
        self.root = self.deleterecursive(self.root, ipaddress)

    def deleterecursive(self, node, ipaddress):
        if node is None: return node
        if ipaddress < node.ip:
            node.left = self.deleterecursive(node.left, ipaddress)
        elif ipaddress > node.ip:
            node.right = self.deleterecursive(node.right, ipaddress)
        else:
            if node.left is None: return node.right
            elif node.right is None: return node.left
            temp = self.minvalue(node.right)
            node.ip = temp.ip
            node.right = self.deleterecursive(node.right, temp.ip)
        return node

    def minvalue(self, node):
        current = node
        while current.left is not None: current = current.left
        return current
    
    def get_all_ips(self):
        # In-Order Traversal to get IPs sorted
        result = []
        self._inorder(self.root, result)
        return result
    
    def _inorder(self, node, result):
        if node:
            self._inorder(node.left, result)
            result.append(node.ip)
            self._inorder(node.right, result)

# ==========================================
# LAB 6: Stack Implementation
# ==========================================
class StackNode:
    def __init__(self, data):
        self.data = data
        self.next = None

class AlertStack:
    def __init__(self):
        self.top = None
        self.size = 0

    def push(self, alert):
        newnode = StackNode(alert)
        newnode.next = self.top
        self.top = newnode
        self.size += 1

    def pop(self):
        if self.isempty(): return None
        data = self.top.data
        self.top = self.top.next
        self.size -= 1
        return data

    def isempty(self):
        return self.top is None

# ==========================================
# LAB 9: Graph Data Structure
# ==========================================
class NetworkGraph:
    def __init__(self):
        self.adjlist = {}

    def addconnection(self, src, dst):
        if src not in self.adjlist:
            self.adjlist[src] = set()
        self.adjlist[src].add(dst)
        
    def get_connections(self):
        return self.adjlist
