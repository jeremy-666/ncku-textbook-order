#include<stdio.h>
#include<stdlib.h>
#include<string.h>

typedef struct tree_node
{
    int val;
    struct tree_node * left;
    struct tree_node * right;
}tree_node;

tree_node* make_tree_pre (int* inorder , int* preorder , int in_start , int in_end , int pre_start , int pre_end , int* number_to_index_in_inorder)
{
    if (in_start > in_end || pre_start > pre_end) return NULL;
    int curr_num = preorder[pre_start];
    int curr_num_index_in_inorder = number_to_index_in_inorder[curr_num];
    int left_tree_node_count = curr_num_index_in_inorder - in_start;

    tree_node* curr_node = (tree_node*) malloc (1 * sizeof(tree_node));
    curr_node -> val = curr_num;
    curr_node -> left = make_tree_pre(inorder , preorder , in_start , curr_num_index_in_inorder - 1 , pre_start + 1 , pre_start + left_tree_node_count , number_to_index_in_inorder);
    curr_node -> right = make_tree_pre(inorder , preorder , curr_num_index_in_inorder + 1 , in_end , pre_start + left_tree_node_count + 1 , pre_end , number_to_index_in_inorder);

    return curr_node;
}

tree_node* make_tree_post (int* inorder , int* postorder , int in_start , int in_end , int post_start , int post_end , int* number_to_index_in_inorder)
{
    if (in_start > in_end || post_start > post_end) return NULL;
    int curr_num = postorder[post_end];
    int curr_num_index_in_inorder = number_to_index_in_inorder[curr_num];
    int left_tree_node_count = curr_num_index_in_inorder - in_start;

    tree_node* curr_node = (tree_node*) malloc (1 * sizeof(tree_node));
    curr_node -> val = curr_num;
    curr_node -> left = make_tree_post(inorder , postorder , in_start , curr_num_index_in_inorder - 1 , post_start , post_start + left_tree_node_count - 1 , number_to_index_in_inorder);
    curr_node -> right = make_tree_post(inorder , postorder , curr_num_index_in_inorder + 1 , in_end , post_start + left_tree_node_count , post_end - 1 , number_to_index_in_inorder);

    return curr_node;
}


int main()
{
    int n;
    scanf("%d" , &n);

    int* inorder = (int*) malloc (n * sizeof(int));
    int* pre_or_post = (int*) malloc (n * sizeof(int));

    char order_type[15]; // 記下來是pre還是post

    for (int i = 0 ; i < 2 ; i ++)
    {
        char input_order_type[15];
        scanf("%s" , input_order_type);

        if (strcmp(input_order_type , "inorder") == 0)
        {
            int a;
            for (int k = 0 ; k < n ; k ++)
            {
                scanf("%d" , &a);
                inorder[k] = a;
            }
        }
        else
        {
            strcpy(order_type , input_order_type);
            int a;
            for (int k = 0 ; k < n ; k ++)
            {
                scanf("%d" , &a);
                pre_or_post[k] = a;
            }
        }
    }

    int* number_to_index_in_inorder = (int *) malloc ((n + 1) * sizeof(int));

    for (int i = 0 ; i < n ; i ++)
    {
        number_to_index_in_inorder[inorder[i]] = i; // 讓數字去對應在inorder陣列裡面的index位置
    }

    tree_node* tree_root = NULL;

    if (strcmp(order_type , "preorder") == 0)
    {
        tree_root = make_tree_pre(inorder , pre_or_post , 0 , n - 1 , 0 , n - 1 , number_to_index_in_inorder);
    }
    else
    {
        tree_root = make_tree_post(inorder , pre_or_post , 0 , n - 1 , 0 , n - 1 , number_to_index_in_inorder);
    }

    //這裡開始 level_order_traverse
    tree_node* queue[1000];
    int front = 0;
    int back = 0;

    queue[back] = tree_root;
    back ++;

    while (back > front)
    {
        int level_node_count = back - front;
        
        for (int i = 0 ; i < level_node_count ; i ++)
        {
            tree_node* curr_node = queue[front];
            front ++;
            printf("%d " , curr_node -> val);
            if (curr_node -> left != NULL)
            {
                queue[back] = curr_node -> left;
                back ++;
            }
            if (curr_node -> right != NULL)
            {
                queue[back] = curr_node -> right;
                back ++;
            }
        }
    }
    return 0;
    
}
