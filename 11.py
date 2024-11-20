import hashlib

def create_md5_file(input_file_path, output_file_path):
    """
    计算输入文件的 MD5 值并将其写入输出文件。
    @param input_file_path: 输入文件的路径。
    @param output_file_path: 输出文件的路径，MD5 值将写入此文件。
    """
    # 计算 MD5 值
    with open(input_file_path, 'rb') as f:
        file_content = f.read()  # 读取文件内容
        md5_value = hashlib.md5(file_content).hexdigest()  # 计算 MD5 值

    # 将 MD5 值写入输出文件
    with open(output_file_path, 'w') as f:
        f.write(md5_value)  # 写入 MD5 值

    print(f"MD5 value of the file '{input_file_path}' is: {md5_value}")
    print(f"MD5 value has been written to '{output_file_path}'.")

# 示例使用
input_file = r'C:\Users\elysia\Desktop\第三学期\111.txt'  # 输入文件
output_file = r'C:\Users\elysia\Desktop\第三学期\111_md5.txt'  # 输出文件
create_md5_file(input_file, output_file)  # 调用函数