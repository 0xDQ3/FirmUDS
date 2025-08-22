from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import Reference
from ghidra.framework.model import DomainFile
from ghidra.program.model.listing import Program
from ghidra.util import Msg
#from ghidra.framework import askString
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from openai import OpenAI
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from datetime import datetime
Chat_history = []
# Ghidra Python Script to Rename a Function
# @category: Example
# @author: Your Name

from ghidra.program.model.symbol import SourceType

# 日志功能（固定写入脚本同目录 logs/）
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except Exception:
    BASE_DIR = os.getcwd()
LOG_DIR = os.path.join(BASE_DIR, "logs")
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except Exception:
    pass
LOG_FILE = os.path.join(LOG_DIR, "log.txt")
ERR_STATE_FILE = os.path.join(LOG_DIR, "llm_error_state.json")

# ==================== LLM 客户端配置区域 ====================
# 在这里统一配置所有LLM客户端的API密钥、URL和模型名称
LLM_CONFIG = {
    "qwen": {
        "api_key": "sk-xxxxx",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-max-2025-01-25"
    },
    "moonshot": {
        "api_key": "sk-xxxxx",
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-32k"
    },
    "deepseek": {
        "api_key": "sk-xxxx",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v3"
    }
}

# 默认使用的LLM客户端（可在此处快速切换）
DEFAULT_LLM = "qwen"

def get_llm_client(client_name=None):
    """
    获取LLM客户端实例
    :param client_name: 客户端名称，如 "qwen", "moonshot", "deepseek"
    :return: OpenAI客户端实例
    """
    if client_name is None:
        client_name = DEFAULT_LLM
    
    if client_name not in LLM_CONFIG:
        print(f"[WARNING] 未找到客户端配置: {client_name}，使用默认客户端: {DEFAULT_LLM}")
        client_name = DEFAULT_LLM
    
    config = LLM_CONFIG[client_name]
    return OpenAI(
        api_key=config["api_key"],
        base_url=config["base_url"]
    )

def get_llm_model(client_name=None):
    """
    获取LLM模型名称
    :param client_name: 客户端名称
    :return: 模型名称字符串
    """
    if client_name is None:
        client_name = DEFAULT_LLM
    
    if client_name not in LLM_CONFIG:
        client_name = DEFAULT_LLM
    
    return LLM_CONFIG[client_name]["model"]

def write_log(message):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] {message}\n")
    except Exception:
        pass

def save_llm_error_state(state):
    try:
        state_with_ts = dict(state or {})
        state_with_ts["timestamp"] = datetime.now().isoformat()
        with open(ERR_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state_with_ts, f, ensure_ascii=False, indent=2)
        write_log("[LLM_ERROR_STATE] saved to llm_error_state.json")
    except Exception as e:
        write_log(f"[LLM_ERROR_STATE_SAVE_FAIL] {e}")

def load_llm_error_state():
    try:
        if os.path.exists(ERR_STATE_FILE):
            with open(ERR_STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            write_log("[LLM_ERROR_STATE] loaded from llm_error_state.json")
            return data
    except Exception as e:
        write_log(f"[LLM_ERROR_STATE_LOAD_FAIL] {e}")
    return None

def log_separator(title):
    sep = "=" * 20
    write_log(f"{sep} {title} {sep}")

_original_print = print
def print(*args, **kwargs):
    msg = " ".join(str(a) for a in args)
    write_log(msg)
    return _original_print(*args, **kwargs)

def write_stage_log(stage_index, payload):
    filename = os.path.join(LOG_DIR, f"log_{stage_index}.txt")
    try:
        if isinstance(payload, (dict, list)):
            content = json.dumps(payload, ensure_ascii=False, indent=2)
        else:
            content = str(payload)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        pass

def rename_function(old_name, new_name):
    """
    Rename a function from old_name to new_name.
    :param old_name: The current name of the function.
    :param new_name: The new name to be assigned to the function.
    :return: A tuple (success, message)
    """
    # Get the current program
    program = currentProgram()
    function_manager = program.getFunctionManager()

    # Find the function by old_name
    functions = function_manager.getFunctions(True)  # Get all functions
    func = None
    for f in functions:
        if f.getName() == old_name:
            func = f
            break

    if func is None:
        return False, f"Function with name '{old_name}' not found."

    # Rename the function
    try:
        func.setName(new_name, SourceType.USER_DEFINED)
        return True, f"Function '{old_name}' successfully renamed to '{new_name}'."
    except Exception as e:
        return False, f"Failed to rename function '{old_name}' to '{new_name}': {e}"


    
   
def get_decompilation(func_name):
    """
    输入函数名称，返回对应的反编译代码
    """
    program = currentProgram()
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    func = getFunction(func_name)
    if not func:
        print(f"未找到函数: {func_name}")
        return

    res = decompiler.decompileFunction(func, 0, monitor())
    decompiled = res.getDecompiledFunction()
    if decompiled:
        print("Decompiled Code:")
        print(decompiled.getC())
        return str(decompiled.getC())
    else:
        print("反汇编失败。")

def getFunction(func_name):
    """
    根据函数名称获取函数对象。
    """
    program = currentProgram()
    funcs = program.getListing().getFunctions(True)
    for func in funcs:
        if func.getName() == func_name:
            return func
    return None



def get_cross_references(func_name):
    """
    输入函数名称，返回该函数被其他函数调用的交叉引用列表。
    """
    program = currentProgram()
    func = getFunction(func_name)
    if not func:
        print(f"未找到函数: {func_name}")
        return []

    references = []
    addr = func.getEntryPoint()
    for ref in program.getReferenceManager().getReferencesTo(addr):
        if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL or ref.getReferenceType() == RefType.CONDITIONAL_CALL:
            from_func = program.getListing().getFunctionContaining(ref.getFromAddress())
            if from_func:
                references.append(from_func.getName())
    return references

def print_cross_references(func_name,type):
    if type =="FUN":
        refs = get_cross_references(func_name)
    else:
        results = find_symbol_references(func_name)
        refs =[]
        if results:
            for addr, name in sorted(set(results)):  # 去重
                refs.append("{}".format(name))
            refs = set(refs)
        else:
            refs = None

    if refs:
        print(f"函数 '{func_name}' 的交叉引用函数列表:")
        for ref in refs:
            print(ref)
        return refs
    else:
        print(f"函数 '{func_name}' 没有交叉引用。")
        return None
    



def LLMs_explain(client, code, LLMs_Object,json_structure,input,old_commend):
    global Chat_history
    sys_content = f"你是一个反编译程序分析专家，你尤其了解Ghidra和汽车UDS相关的功能。记住，不要陷入逻辑死循环！目前已经执行过的旧请求为{old_commend}，接下来不要有重复的[进一步请求]。另外"+LLMs_Object
    
    user_meag = "为你提供"+code+"请你分析。"+input+"请用json结构输出```json"+json_structure+"```"
    user_input = {"role": "user", "content": user_meag}
    Chat_history.append(user_input)

            try:
            completion = client.chat.completions.create(
                model=get_llm_model(),
                messages=[{"role": "system", "content": sys_content}]+Chat_history
            )
        GPT_text = completion.choices[0].message.content
        print(GPT_text)
        Chat_history.append({"role": "assistant", "content": GPT_text})
        json_pattern = r"```json(.*?)```"
        match = re.search(json_pattern, GPT_text, re.DOTALL)
        if match:
            json_str = match.group(1).strip().replace("\n"," ").replace('\\', '\\\\')
            try:
                json_data = json.loads(json_str)
            except json.JSONDecodeError:
                print("Invalid JSON format.")
                json_data = None
        else:
            try:
                json_data = json.loads(GPT_text)
            except Exception:
                json_data = None
        if json_data is None:
            # 保存错误上下文
            save_llm_error_state({
                "phase": "LLMs_explain",
                "sys_content": sys_content,
                "Chat_history": Chat_history,
                "raw_output": GPT_text,
                "json_structure": json_structure
            })
            print("[LLM_PARSE_ERROR] 已保存错误上下文以便恢复。")
            # 返回一个明确的占位结果以避免崩溃
            return {"是否完成目标": {"result": "no", "reason": "LLM响应解析失败"}}
        return json_data
    except Exception as e:
        # 保存错误上下文
        save_llm_error_state({
            "phase": "LLMs_explain_exception",
            "error": str(e),
            "sys_content": sys_content,
            "Chat_history": Chat_history,
            "json_structure": json_structure
        })
        print(f"[LLM_CALL_ERROR] {e}，已保存错误上下文以便恢复。")
        return {"是否完成目标": {"result": "no", "reason": "LLM调用异常"}}

def LLMs_explain_deepseek(client, code, LLMs_Object,json_structure,input):
    global Chat_history
    sys_content = "你是一个反编译程序分析专家，你尤其了解Ghidra和汽车UDS相关的功能。记住，不要陷入逻辑死循环！不要有重复的[进一步请求]。另外"+LLMs_Object+"请用json结构输出```json"+json_structure+"```"
    
    user_meag = "为你提供【当前函数】:"+code+"请你分析。"+input

    Chat_history.append(HumanMessage(content=user_meag))
    messages=[SystemMessage(content=sys_content)]+Chat_history

    GPT_text = GPT_text = client.invoke(messages).content
    print(GPT_text)
    Chat_history.append(HumanMessage(content=GPT_text))
    json_pattern = r"```json(.*?)```"
    match = re.search(json_pattern, GPT_text, re.DOTALL)
    if match:
        json_str = match.group(1).strip().replace("\n"," ").replace('\\', '\\\\').replace("：",":").replace("‘",'"').replace("’",'"').replace("”",'"').replace("“",'"')# 获取匹配的字符串并去除前后空格
        try:
            # 将提取的字符串转换为 JSON
            json_data = json.loads(json_str)
        except json.JSONDecodeError:
            print("Invalid JSON format.")
    else:
        json_data = json.loads(GPT_text).replace("\n"," ")
        # 打印 'recommad' 属性的值
    return json_data


#A -> B -> C和函数情况没考虑
def find_leaf_nodes(relationships):
    # 创建一个集合来存储所有节点
    all_nodes = set()
    # 创建一个集合来存储非叶节点（即有出边的节点）
    non_leaf_nodes = set()
    
    # 遍历关系列表
    for relation in relationships:
        # 分割关系，获取源节点和目标节点
        source, target = relation.split("->")
        # 将源节点和目标节点加入所有节点集合
        source = source.replace(" ","")
        target = target.replace(" ","")
        all_nodes.add(source)
        all_nodes.add(target)
        # 将源节点加入非叶节点集合
        non_leaf_nodes.add(source)
    
    # 叶节点是所有节点中不在非叶节点集合中的节点
    leaf_nodes = all_nodes - non_leaf_nodes
    
    return list(leaf_nodes), list(non_leaf_nodes)
def filter_and_group_leaf_nodes(leaf_nodes):
    # 分类：DAT_ 开头的变量和 FUN_ 开头的函数
    dat_nodes = sorted([node for node in leaf_nodes if node.startswith("DAT_")], key=lambda x: int(x.split("_")[1], 16))
    fun_nodes = [node for node in leaf_nodes if node.startswith("FUN_")]

    # 用于存储最终结果
    result = []

    # 处理 DAT_ 开头的变量
    if dat_nodes:
        groups = []
        current_group = [dat_nodes[0]]

        for i in range(1, len(dat_nodes)):
            # 提取数值部分并比较是否连续
            current_value = int(dat_nodes[i].split("_")[1], 16)
            previous_value = int(dat_nodes[i - 1].split("_")[1], 16)

            if current_value == previous_value + 1:
                current_group.append(dat_nodes[i])
            else:
                groups.append(current_group)
                current_group = [dat_nodes[i]]
        
        # 添加最后一个组
        groups.append(current_group)

        # 将连续的组合并为数组，非连续的单独返回
        for group in groups:
            if len(group) > 1:
                # 合并为数组
                base_name = min(group)
                result.append(f"{base_name}[]")
            else:
                # 单独返回
                result.extend(group)

    # 添加 FUN_ 开头的函数
    result.extend(fun_nodes)

    return result
def find_variable_relationships(code, target_var):
    seed_relationships = []
    relationships = {}
    queue = [target_var]
    visited = set()

    lines = code.split('\n')
    # 预处理，提取所有可能的变量关系
    for line in lines:
        line = line.strip()
        # 匹配赋值语句，如 uVar1 = DAT_7001365c
        if '=' in line:
            parts = line.split('=', 1)
            if len(parts) >= 2:
                left = parts[0].strip()
                right = parts[1].strip().split(';')[0].strip()  # 去掉可能的分号
                # 提取右侧变量
                right_vars = re.findall(r'\b(\w+)\b', right)
                # 保存左右变量的关系
                for var in right_vars:
                    if var not in relationships:
                        relationships[var] = set()
                    relationships[var].add(left)
    
    # BFS 找出所有和目标变量相关联的变量
    while queue:
        current_var = queue.pop(0)
        if current_var not in visited:
            visited.add(current_var)
            # 找出当前变量的所有目标变量（即被赋值的变量）
            if current_var in relationships:
                for var in relationships[current_var]:
                    seed_relationships.append(f"{current_var} -> {var}")
                    if var not in visited:
                        queue.append(var)

    return seed_relationships
def get_target_symbol(symbol_name):
    symbol_table = currentProgram().getSymbolTable()
    return next((s for s in symbol_table.getSymbols(symbol_name) if s.getName() == symbol_name), None)

def get_sorted_dat_symbols():
    return sorted(
        [s for s in currentProgram().getSymbolTable().getAllSymbols(True) if s.getName().startswith("DAT_")],
        key=lambda x: x.getAddress()
    )
def read_machine_code_between_addresses(start_addr, end_addr):
    """
    读取两个地址之间的所有机器码。

    参数:
        start_addr (str): 起始地址（例如 "0x1000"）
        end_addr (str): 结束地址（例如 "0x2000"）

    返回:
        list: 两个地址之间的机器码字节列表
    """
    # 将字符串地址转换为 Ghidra 的 Address 对象
    start_address = start_addr
    end_address = end_addr

    # 创建地址范围
    addr_set = AddressSet(start_address, end_address)

    # 获取当前程序的代码单元
    code_units = currentProgram().getListing().getCodeUnits(addr_set, True)

    machine_code = []
    for code_unit in code_units:
        # 获取代码单元的机器码字节
        bytes = code_unit.getBytes()
        machine_code.extend(bytes)

    return machine_code
def get_global_variable_data(symbol_name):
    target_symbol = get_target_symbol(symbol_name)
    if not target_symbol:
        print(f"[錯誤] 找不到符號: {symbol_name}")
        return None
    dat_symbols = get_sorted_dat_symbols()
    try:
        current_index = dat_symbols.index(target_symbol)
    except ValueError:
        print(f"[錯誤] 符號 {symbol_name} 不在 DAT_ 符號列表中")
        return None
    if current_index + 1 >= len(dat_symbols):
        print("[錯誤] 沒有後續的 DAT_ 符號")
        return None
    start_addr = target_symbol.getAddress()
    next_symbol = dat_symbols[current_index + 1]
    end_addr = next_symbol.getAddress()
    if end_addr <= start_addr:
        print("[錯誤] 下一個符號地址必須大於當前符號地址")
        return None
    data = read_machine_code_between_addresses(start_addr, end_addr)
    if len(data) == 0:
        return None
    else:
        print(f"從 {start_addr} 到 {end_addr} 的數據 (共 {len(data)} 字節):")
        # 分組顯示十六進制
        hex_str = ' '.join(f"{b & 0xFF:02X}" for b in data)
        print(hex_str)
        return hex_str
def get_called_functions(function_name):
    """
    输入函数名称，返回该函数调用的所有函数名称列表
    :param function_name: 要查询的函数名称字符串
    :return: 被调用函数名称列表（可能包含重复项）
    """
    program = currentProgram()
    function_manager = program.getFunctionManager()
    
    # 在全局范围查找目标函数
    target_func = None
    for func in function_manager.getFunctions(True):  # True 表示前向遍历
        if func.getName() == function_name:
            target_func = func
            break
    
    if not target_func:
        print("未找到函数: {}".format(function_name))
        return []
    
    # 获取被调用函数集合
    called_functions = target_func.getCalledFunctions(getMonitor())
    
    # 提取函数名称并返回
    return [func.getName() for func in called_functions]
def find_symbol_references(symbol_name):
    program = currentProgram()
    symbol_table = program.getSymbolTable()
    symbols = list(symbol_table.getSymbols(symbol_name))
    
    if not symbols:
        print("未找到符號: {}".format(symbol_name))
        return []
    
    symbol = symbols[0]
    symbol_addr = symbol.getAddress()
    target_addr = symbol_addr.getOffset()  # 獲取數值形式的地址
    target_addr = target_addr & 0xFFFF
    print(f"target_addr{hex(target_addr)}")
    # 方法1：通過引用管理器獲取顯式引用
    ref_manager = program.getReferenceManager()
    explicit_refs = ref_manager.getReferencesTo(symbol_addr)
    
    # 方法2：掃描所有指令中的立即數操作數
    implicit_refs = []
    mem = program.getMemory()
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        
        addr_set = AddressSet(block.getStart(), block.getEnd())
        monitor = ConsoleTaskMonitor()
        for instr in program.getListing().getInstructions(addr_set, True):
            operands = instr.getOpObjects(1)  # 獲取所有操作數
            for op in operands:
                if hasattr(op, 'getValue'):
                    op_value = op.getValue()
                    if op_value == target_addr:
                        implicit_refs.append(instr.getAddress())
    
    # 合併結果
    results = []
    # 處理顯式引用
    for ref in explicit_refs:
        from_addr = ref.getFromAddress()
        func = getFunctionContaining(from_addr)
        results.append((from_addr, func.getName() if func else "未知函數"))
    
    # 處理隱式引用（立即數）
    for addr in implicit_refs:
        func = getFunctionContaining(addr)
        results.append((addr, func.getName() if func else "未知函數"))
   
    return results
def join_strings(function_list):
    """
    将列表中的元素用回车隔开拼接成一个字符串

    :param function_list: 包含字符串元素的列表
    :return: 拼接后的字符串
    """
    # 过滤掉 None，确保拼接安全
    safe_list = [s for s in function_list if isinstance(s, str)]
    return '\n'.join(safe_list)
def Looking_for_suspicious_UDS27():
    current_program = getCurrentProgram()
    if current_program is None:
        print("No program loaded.")
        return

    # Initialize the decompiler interface
    decompiler = DecompInterface()
    decompiler.openProgram(current_program)

    # Corrected line: Directly get the FunctionManager from current_program
    function_manager = current_program.getFunctionManager()
    functions = function_manager.getFunctions(True)

    monitor = ConsoleTaskMonitor()

    matching_functions = []

    for function in functions:
        if monitor.isCancelled():
            break

        # Decompile the function
        decompile_result = decompiler.decompileFunction(function, 60, monitor)

        if not decompile_result.decompileCompleted():
            print("Cannot decompile function: {}".format(function.getName()))
            continue

        # Get the decompiled code
        decompiled_code = decompile_result.getDecompiledFunction().getC()

        # Check for UDS27 byte manipulation patterns - must have both << 0x18 and << 0x10
        has_shift_18 = '<< 0x18' in decompiled_code
        has_shift_10 = '<< 0x10' in decompiled_code
        
        # Core requirement: must have both shift operations
        if has_shift_18 and has_shift_10:
            # Additional validation: check if it looks like byte manipulation
            byte_manipulation_indicators = [
                'uint', 'char', 'byte', 'DAT_', '|', '^', '&', '[', ']'
            ]
            indicator_count = sum(1 for indicator in byte_manipulation_indicators 
                                if indicator in decompiled_code)
            
            # Check for array indexing patterns (common in byte operations)
            has_array_ops = '[' in decompiled_code and ']' in decompiled_code
            has_bitwise_ops = '|' in decompiled_code or '^' in decompiled_code or '&' in decompiled_code
            
            # Must have sufficient indicators of byte manipulation
            if indicator_count >= 2 and (has_array_ops or has_bitwise_ops):
                matching_functions.append(function.getName())
                print(f"[UDS27_MATCH] {function.getName()}: has_shift_18={has_shift_18}, "
                      f"has_shift_10={has_shift_10}, has_array_ops={has_array_ops}, "
                      f"has_bitwise_ops={has_bitwise_ops}, indicators={indicator_count}")

    decompiler.dispose()

    if matching_functions:
        print("Functions whose pseudocode contains 0x18, 0x10, and 0x08:")
        for func_name in matching_functions:
            print(" - {}".format(func_name))
    else:
        print("No functions containing 0x18, 0x10, and 0x08 were found.")
    return matching_functions
def merge_tuples(input_list):
    # 创建一个字典，以每个元组的最后一个元素为键
    result_dict = {}
    
    for tup in input_list:
        # 获取元组的最后一个元素作为键
        key = tup[-1]
        # 将元组的其他元素作为值存储到字典中
        result_dict[key] = tup[:-1]
    
    # 将字典的值提取出来，形成新的列表
    result_list = [(values + (key,)) for key, values in result_dict.items()]
    return result_list
def build_seed_map(func_name_list):
    mapping = {}
    for tpl in func_name_list:
        try:
            fn = tpl[-1]
            prev = None
            if len(tpl) == 4:
                # (desc, previous_ref, rand_ref, ref)
                prev = tpl[1]
            elif len(tpl) >= 5:
                # (desc, ref, previous_ref, rand_ref, call_ref)
                prev = tpl[2]
            mapping[fn] = prev
        except Exception:
            continue
    return mapping
if __name__ == "__main__":
    # 启动时尝试恢复上次的LLM错误状态
    resume_state = load_llm_error_state()
    if resume_state:
        try:
            # 尝试恢复 Chat 历史，以便继续上下文
            prev_chat = resume_state.get("Chat_history")
            if isinstance(prev_chat, list):
                Chat_history = prev_chat
                print("[RESUME] Chat history 已恢复，继续执行。")
        except Exception as e:
            print(f"[RESUME_FAIL] {e}")
    #"------------------------------寻找UDS 27特征 <<0x18 <<0x10 <<0x8--------------------------------------------------")
    log_separator("阶段1: matching_functions")
    matching_functions = Looking_for_suspicious_UDS27()
    print(matching_functions)
    write_stage_log(1, {"matching_functions": matching_functions})
    #
    #"------------------------------寻找RAND生成器导火索---1.TRNG 2.LGC 3.二进制相似度比较---------------------------------------------------")
    function_name_list = []#rand备选函数
    rand_input_str = askString("输入二进制相似度分析疑似随机函数为:","例子：'FUN_aaa FUN_bbb FUN_ccc'")
    rand_input_lis = rand_input_str.split()
    _dat_refs = print_cross_references("DAT_f0001010","DAT")
    base_set = set(rand_input_lis)
    if _dat_refs:
        try:
            rand_refs = set(_dat_refs).union(base_set)
        except Exception:
            rand_refs = base_set
    else:
        rand_refs = base_set

    for rand_ref in rand_refs:
        refs = print_cross_references(rand_ref,"FUN")
        if refs:
            # 定义一个辅助函数来递归检查，并限制递归深度
            def check_refs(refs_list, matching_funcs, depth=0, previous_ref=None):
                if depth >= 20:  # 达到最大递归深度，停止递归
                    return None
                for ref in refs_list:
                    if ref in matching_funcs:
                        #print(f"命中{ref}")
                       # print(f"来自{rand_ref}")
                        desc = f"其中{previous_ref if previous_ref else '未知'}用于生成seed，{ref}和Seed2Key函数有关" + get_decompilation(ref)
                        function_name_list.append((desc,previous_ref,rand_ref,ref))
                        return f"其中{previous_ref if previous_ref else '未知'}用于生成seed，{ref}和Seed2Key函数有关" + get_decompilation(ref)
                    else:
                        #这块不够深
                        call_refs = get_called_functions(ref)
                       # print(call_refs)
                        for call_ref in call_refs:
                            if call_ref in matching_funcs:
                               # print(f"命中{call_ref}")
                               # print(f"来自{rand_ref}")
                                desc = f"其中{previous_ref if previous_ref else '未知'}用于生成seed, {call_ref}和Seed2Key函数有关" +get_decompilation(ref) + get_decompilation(call_ref)
                                function_name_list.append((desc,ref,previous_ref,rand_ref,call_ref))
                                return f"其中{previous_ref if previous_ref else '未知'}用于生成seed, {call_ref}和Seed2Key函数有关" +get_decompilation(ref) + get_decompilation(call_ref)
                        sub_refs = print_cross_references(ref, "FUN")
                        if sub_refs:
                            result = check_refs(sub_refs, matching_funcs, depth + 1, ref)  # 传递当前ref作为下一个递归的previous_ref
                            if result:
                                return result
                return None
            result = check_refs(refs, matching_functions)
            if result:
                code = result
                flag = 1
            else:
                code = "未找到相关函数"
    # 在合并前先构建一次种子映射，保留原始链路中的 previous_ref
    seed_map_pre = build_seed_map(function_name_list)
    #合并：
    function_name_list = merge_tuples(function_name_list)
    log_separator("阶段2: ask_index")

    # 并发自动分析：对所有候选函数并行反编译并用LLM判断UDS27特征
    ask_index = [name[-1] for i, name in enumerate(function_name_list[0:])]
    
    # 如果ask_index为空，则使用matching_functions作为备选
    if not ask_index:
        ask_index = matching_functions
        print(f"[FALLBACK] ask_index为空，使用matching_functions作为备选: {ask_index}")
    
    write_stage_log(2, {"ask_index": ask_index})

    # 使用统一的LLM客户端配置
    client_qwen = get_llm_client("qwen")
    client_moonshot = get_llm_client("moonshot")


    def _parse_llm_json(GPT_text):
        json_pattern = r"```json(.*?)```"
        match = re.search(json_pattern, GPT_text, re.DOTALL)
        if match:
            json_str = match.group(1).strip().replace("\n"," ").replace('\\', '\\\\')
            try:
                return json.loads(json_str)
            except Exception:
                return None
        try:
            return json.loads(GPT_text)
        except Exception:
            return None

    def _llm_check_ud27(client, code_text):
        sys_content = (
            "你是一个反编译程序分析专家，你尤其了解Ghidra和汽车UDS相关的功能。"
            + "请判断当前函数是否具备UDS诊断协议27子服务特征,严格分成4个字节或者3个。存在类似“ four = (char)Seed; one = (char)((uint)Seed >> 0x18); two = (char)((uint)Seed >> 0x10); three = (char)((uint)Seed >> 8);”这个片段的函数就是，给出理由。"#"备注：27子服务特征：特征a.严格将4个字节拼成一个值；特征b.一个值拆成4个字节例如存在：“  four = (char)Seed; one = (char)((uint)Seed >> 0x18); two = (char)((uint)Seed >> 0x10); three = (char)((uint)Seed >> 8);”"
        )
        json_structure_hint = "{    \"目标\":\"找到存在UDS 27服务特征的相关函数\"    \"函数逻辑\":\"{string}\",    \"result\":\"yes/no\"    \"reason\":\"xxxx\"}"
        user_meag = "为你提供" + code_text + "请你分析。" + "请用json结构输出```json" + json_structure_hint + "```"
        try:
            completion = client.chat.completions.create(
                model=get_llm_model("qwen"),
                messages=[{"role": "system", "content": sys_content}, {"role": "user", "content": user_meag}],
            )
            GPT_text = completion.choices[0].message.content
            data = _parse_llm_json(GPT_text)
            if data is None:
                save_llm_error_state({
                    "phase": "_llm_check_ud27_parse",
                    "sys_content": sys_content,
                    "user_meag": user_meag,
                    "raw_output": GPT_text
                })
                print("[LLM_PARSE_ERROR] _llm_check_ud27 保存错误上下文以便恢复。")
            return data
        except Exception as e:
            save_llm_error_state({
                "phase": "_llm_check_ud27_exception",
                "error": str(e),
                "sys_content": sys_content,
                "user_meag": user_meag
            })
            print(f"[LLM_CALL_ERROR] _llm_check_ud27 {e}，已保存错误上下文以便恢复。")
            return None

    # 先在主线程顺序获取反编译文本，避免在子线程访问 Ghidra 上下文
    code_items = []
    for fn in ask_index:
        try:
            code_text = get_decompilation(fn)
            if code_text:
                code_items.append({"function": fn, "code": code_text})
        except Exception as e:
            # 忽略单个函数失败，继续
            pass

    # 如果存在恢复状态且包含剩余函数，则仅处理剩余函数
    try:
        if (resume_state or {}).get('remaining_functions'):
            remaining = set(resume_state.get('remaining_functions') or [])
            if remaining:
                code_items = [ci for ci in code_items if ci.get('function') in remaining]
                print(f"[RESUME] 仅处理剩余函数: {list(remaining)}")
    except Exception:
        pass

    # 记录当前待检测的函数列表，便于外部查看和恢复
    try:
        with open(os.path.join(LOG_DIR, "code_items_functions.json"), "w", encoding="utf-8") as f:
            json.dump([ci.get('function') for ci in code_items], f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    def _evaluate_function_llm(item):
        # 仅在子线程调用 LLM，不访问 Ghidra，也不打印
        resp = _llm_check_ud27(client_qwen, item["code"])
        if resp and resp.get("result") == "yes":
            return item
        return None

    log_separator("阶段3: uds27_hits")
    uds27_hits = []
    if code_items:
        for idx, item in enumerate(code_items):
            code_text_for_check = item.get("code") or ""
            crlf_lines = code_text_for_check.split("\r\n")
            if len(crlf_lines) > 120:
                print(f"[SKIP] {item['function']} over 120 CRLF lines: {len(crlf_lines)}")
                continue
            
            resp = _llm_check_ud27(client_qwen, code_text_for_check)
            if resp is None:
                # 记录失败上下文，包含剩余函数，便于下次继续
                try:
                    remaining_functions = [ci.get('function') for ci in code_items[idx:]]
                    save_llm_error_state({
                        "phase": "uds27_stage_error",
                        "failed_function": item.get('function'),
                        "remaining_functions": remaining_functions,
                        "code_items_functions": [ci.get('function') for ci in code_items]
                    })
                    print(f"[ERROR] UDS27判定失败，已记录错误并可下次从 {item.get('function')} 继续。")
                except Exception:
                    pass
                break
            res = "unknown"
            if resp:
                # 支持两类返回结构
                res = resp.get("result") or resp.get("是否完成目标", {}).get("result") or "unknown"
            print(f"[CHECK] {item['function']} -> {res}")
            print(code_text_for_check)  # 打印完整反编译代码
            print(resp.get("reason"))  # 打印原因
            print("---")
           # rand_input_str = askString("debug","debug")
            if res == "yes":
                total_lines = code_text_for_check.splitlines()
                if len(total_lines) < 5:
                    print(f"[SKIP] {item['function']} 代码行数过少: {len(total_lines)} < 5")
                    continue
                uds27_hits.append(item)

    if uds27_hits:
        print("命中的UDS27特征函数与代码片段：")
        for item in uds27_hits:
            fn = item["function"]
            snippet = (item["code"] or "")[:600]
            print(f"[HIT] {fn}\n{snippet}\n---\n")
    else:
        print("未命中UDS27特征函数。")
    try:
        write_stage_log(3, {"code_items": [ci.get('function') for ci in code_items], "uds27_hits": uds27_hits})
    except Exception:
        write_stage_log(3, {"uds27_hits": uds27_hits})

    # 若本阶段成功跑完，且错误状态为UDS27阶段，清理错误状态文件
    try:
        if (resume_state or {}).get('phase', '').startswith('uds27') and os.path.exists(ERR_STATE_FILE):
            os.remove(ERR_STATE_FILE)
            print("[RESUME_CLEAN] 已清理UDS27阶段的错误状态文件。")
    except Exception:
        pass

    # 将命中结果保存为JSON
    try:
        with open("uds27_hits.json", "w", encoding="utf-8") as f:
            json.dump(uds27_hits, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存结果失败: {e}")

    # 后续流程：将命中函数转为队列，逐个进入主循环，并绑定 seed 上下文
    seed_map_post = build_seed_map(function_name_list)
    seed_map = dict(seed_map_post)
    try:
        _ = seed_map_pre
    except NameError:
        seed_map_pre = {}
    for k, v in seed_map_pre.items():
        if v is not None:
            seed_map[k] = v
    
    # 如果ask_index来自matching_functions，则所有seed都设为None
    if not function_name_list:
        seed_map = {fn: None for fn in ask_index}
        print(f"[SEED_RESET] ask_index来自matching_functions，所有seed设为None")

    # 加载第4阶段的结果作为第5阶段输入
    def load_uds27_overview():
        try:
            overview_path = os.path.join(LOG_DIR, "uds27_overview.json")
            if os.path.exists(overview_path):
                with open(overview_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"加载uds27_overview.json失败: {e}")
        return None
    code_queue = []
    if uds27_hits:
        for item in uds27_hits:
            fn = item.get("function")
            code_queue.append({
                "function": fn,
                "code": item.get("code"),
                "seed": seed_map.get(fn)
            })
    else:
        code_queue.append({"function": None, "code": "未找到相关函数", "seed": None})
    print(code_queue)
    # 初始化主循环上下文为第一个元素
    current = code_queue.pop(0) if code_queue else {"function": None, "code": "未找到相关函数", "seed": None}
    code = current.get("code")
    current_seed = current.get("seed")
    # 使用统一的LLM客户端配置
    client_deepseek = get_llm_client("deepseek")
    function_list = []
    commend_list = []
    Index = 0
    loop_count = 0  # 限制循环次数
    json_structure =[#"{    \"目标\":\"找到生成随机数的相关函数\"    \"函数逻辑\":\"{string}\",    \"进一步请求\":{            \"type\":\"{string}\",            \"target_function_name\":\"{string}\",            \"reason\":\"{string}\"    },    \"是否完成目标\":{            \"result\":\"yes/no\",            \"reason\":\"{string}\",          \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]    }}",
                     "{    \"目标\":\"找到存在UDS 27服务特征的相关函数\"    \"函数逻辑\":\"{string}\",    \"进一步请求\":{        \"type\":\"get_decompilation/get_cross_references\",        \"target_function_name\":\"{string}\"    },    \"是否完成目标\":{        \"result\":\"yes/no\",        \"符合的特征\":[],        \"reason\":\"{string}\"          \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]    }}",
                    # "{    \"目标\":\"逆向UDS协议27子服务中seed传递确定Seed2Key代码\"    \"分析整个函数的逻辑\":\"{string}\",    \"确定随机种子seed变量\":\"{string}\",    \"seed变量传递关系\":\"[\"string\",\"string\",...]\",    \"分析哪些步骤不完备\":\"{string}\",    \"进一步请求\":{        \"type\":\"{string}\",        \"target_fuc_or_val\":\"{string}\"},    \"是否完成目标\":{        \"result\":\"yes/no\",        \"reason\":\"{string}\",        \"related_code\":\"{code}\"        \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]}}",
                     "{    \"目标\":\"逆向UDS协议27子服务中seed传递确定Seed变量\"    \"分析整个函数的逻辑\":\"{string}\",    \"确定随机种子seed变量\":\"{string}\",    \"seed变量传递关系\":\"[\"string\",\"string\",...]\",   \"是否完成目标\":{        \"result\":\"yes\",        \"reason\":\"{string}\",        \"related_code\":\"{code}\"        \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]}}",
                     "{    \"目标\":\"逆向UDS协议27子服务中seed传递确定Seed2Key代码\"    \"函数逻辑\":\"{string}\",    \"seed变量传递关系\":\"{string}\",    \"步骤完备分析\":\"{string}\",    \"进一步请求\":{        \"type\":\"{string}\",        \"target_fuc_or_val\":\"{string}\"    },    \"是否完成目标\":{        \"result\":\"yes/no\",        \"reason\":\"{string}\"        \"related_code\":\"{code}\"          \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]    }}",
                    #   "{    \"目标\":\"逆向当前Seed2Key代码，确认安全密钥是否以硬编码形式存在\"    \"函数逻辑\":\"{string}\",    \"Seed相关变量\":\"{string}\",    \"安全密钥相关变量\":\"{string}\",    \"Key相关变量\":\"{string}\",    \"进一步请求\":{        \"type\":\"{string}\",        \"target_fuc_or_val\":\"[{string}...]\"    },    \"是否完成目标\":{        \"result\":\"yes/no\",        \"reason\":\"{string}\"        \"related_code\":\"{code}\"          \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]    }}",
                     "{    \"目标\":\"确认当前所有历史代码中UDS协议27子服务的功能是否齐全\"    \"功能判定\":{ \"seed_generate\":\"yes/no\", \"seed_split\":\"yes/no\", \"seed2key\":\"yes/no\", \"key_compare\":\"yes/no\" },    \"相关函数\":{ \"seed_generate\":[\"{string}\"...], \"seed_split\":[\"{string}\"...], \"seed2key\":[\"{string}\"...], \"key_compare\":[\"{string}\"...] },    \"是否完成目标\":{ \"result\":\"yes/no\", \"reason\":\"{string}\" } }",
                     "{    \"目标\":\"扫描UDS27代码中的逻辑漏洞\"    \"漏洞分析\":{ \"information_leakage\":{ \"hardcoded_keys\":[\"{string}\"...], \"sensitive_data\":[\"{string}\"...] }, \"algorithmic_flaws\":{ \"weak_seed2key\":[\"{string}\"...], \"short_keys\":[\"{string}\"...] }, \"auth_logic_flaws\":{ \"weak_randomness\":[\"{string}\"...], \"replay_vulnerable\":[\"{string}\"...] } },    \"进一步请求\":{        \"type\":\"get_decompilation/get_cross_references/get_global_var\",        \"target_fuc_or_val\":\"{string}\"    },    \"是否完成目标\":{        \"result\":\"yes/no\",        \"reason\":\"{string}\",        \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]    }}"
                    
                    ]
    LLMs_Object = [#"当前目标：确认rand函数。备注：rand是随机函数, 可能通过线性同余法生成器（LCG）实现，或者硬件TRNG寄存器一定是随机函数(TC399芯片常存在DAT_f0001010)。请你按如下步骤分析：1.先分析整个函数的逻辑。2.给出你希望进一步分析的某个函数（可选操作：1.得到目标函数的反编译内容（即.获得目标函数内容，在type中输入get_decompilation）。2.得到目标函数的交叉引用（即.获得哪些函数调用了目标函数，在type中输入get_cross_references））。3.判断是否完成目标，然后将当前分析过的所有函数的函数名重新命名以总结其功能。",
                   "当前目标：寻找具有UDS诊断协议27子服务特征。备注：27子服务特征：特征a.将4个字节拼成一个值；特征b.一个值拆成4个字节；。另外当前推断seed变量为：" + str(current_seed) + "。请你按如下步骤分析：1.先分析整个函数的逻辑。2.给出你希望进一步分析的某个函数（可选操作：1.得到当前函数的交叉引用（即.获得哪些函数调用了当前函数，在type中输入get_cross_references））。3.判断是否完成目标(并将符合的特征类型存到json中)，然后将当前分析过的所有函数的函数名重新命名以总结其功能。",
                   #"当前目标：逆向UDS协议27子服务中seed传递确定Seed2Key代码。【备注】：27子服务主要负责处理安全挑战，一般生成随机种子(Seed),程序一方面会将Seed通过CAN总线发送出去，另一方面：(i)第一种情况程序会对这Seed（e.g.0x12345678）进行拆分成4个或者3个字节(0x12，0x34，0x56，0x78)，之后进行Seed2Key算法将Seed通过一系列运算成key，然后与总线接收来自挑战者的key进行比较判断是否挑战成功。(ii)第二种情况类似程序会对这seed（可能3~4个字节，e.g.0x12，0x34，0x56，0x78）进行合并成一个值(e.g.0x12345678)，之后进行Seed2Key算法生成key(0xabcdefgh)，然后将key进行拆分成字节，然后与总线接收来自挑战者的key进行比较判断是否挑战成功。请你按如下步骤分析：1.先分析整个函数的逻辑.2.根据历史记录找到生成随机种子函数，确定哪个变量是随机种子，3.请你追踪随机种子Seed的传递逻辑【注意:要将代码的每一行都看全，不要有遗漏。并且传递关系可能有多条】（给出变量传递关系图 A->B->C），目前UDS27服务逻辑是不完备的，一般是寻找变量传递关系的最后某个全局变量的交叉引用，以寻找未出现的逻辑，请你分析哪些步骤不完备（Seed字节操作，Seed2Key转换，Key字节操作，Key值比较校验真假）。4.为了找到Seed2Key转换函数，请分析Seed变量传递链，如果最终传递到全局中则去寻找全局变量的交叉引用；如果传到未知函数中了，请查看未知函数的反编译结果进一步分析（可选操作：1.得到目标函数的反编译内容（即.获得目标函数内容，在type中输入get_decompilation）。2.得到某个全局变量的交叉引用（即.获得哪些函数使用了这个全局变量，在type中输入get_cross_references））5.判断是否完成目标。",
                   "当前目标：逆向UDS协议27子服务中seed传递确定Seed2Key代码。【备注】：27子服务主要负责处理安全挑战，一般生成随机种子(Seed),程序一方面会将Seed通过CAN总线发送出去，另一方面：(i)第一种情况程序会对这Seed（e.g.0x12345678）进行拆分成4个或者3个字节(0x12，0x34，0x56，0x78)，之后进行Seed2Key算法将Seed通过一系列运算成key，然后与总线接收来自挑战者的key进行比较判断是否挑战成功。(ii)第二种情况类似程序会对这seed（可能3~4个字节，e.g.0x12，0x34，0x56，0x78）进行合并成一个值(e.g.0x12345678)，之后进行Seed2Key算法生成key(0xabcdefgh)，然后将key进行拆分成字节，然后与总线接收来自挑战者的key进行比较判断是否挑战成功。请你按如下步骤分析：1.先分析整个函数的逻辑.2.根据历史记录找到生成随机种子函数，确定哪个变量是随机种子，3.请你追踪随机种子Seed的传递逻辑【注意:要将代码的每一行都看全，不要有遗漏。并且传递关系可能有多条】（给出变量传递关系图 A->B->C）。4.判断是否完成目标,然后将当前分析过的所有函数的函数名重新命名以总结其功能。",

                   "当前目标：逆向UDS协议27子服务中seed传递确定主要Seed2Key代码。【备注】：27子服务主要负责处理安全挑战，一般生成随机种子(Seed),程序一方面会将Seed通过CAN总线发送出去，另一方面：(i)第一种情况程序会对这Seed（e.g.0x12345678）进行拆分成4个或者3个字节(0x12，0x34，0x56，0x78)，之后进行Seed2Key算法将Seed通过一系列运算成key，然后与总线接收来自挑战者的key进行比较判断是否挑战成功。(ii)第二种情况类似程序会对这seed（可能3~4个字节，e.g.0x12，0x34，0x56，0x78）进行合并成一个值(e.g.0x12345678)，之后进行Seed2Key算法生成key(0xabcdefgh)，然后将key进行拆分成字节，然后与总线接收来自挑战者的key进行比较判断是否挑战成功。请你按如下步骤分析：1.根据历史记录找到生成随机种子函数，确定哪个变量是随机种子2.请你追踪随机种子Seed的传递逻辑（给出变量传递关系图 A->B->C），目前UDS27服务逻辑是大体完备的，请你分析步骤（Seed字节操作，Seed2Key转换，Key字节操作，Key值比较校验真假）。3.为了找到Seed2Key转换函数，给出你希望进一步分析哪个变量或者函数（可选操作：1.得到目标函数的反编译内容（即.获得目标函数内容，在type中输入get_decompilation）。2.得到当前函数的交叉引用（即.获得哪些函数调用了目标函数，在type中输入get_cross_references）。4.判断是否完成目标,然后将当前分析过的所有函数的函数名重新命名以总结其功能。",
                   "当前目标： 确认当前所有历史代码中UDS协议27子服务的功能是否齐全，包括1.Seed产生。 2.Seed切割 3. Seed2Key算法 4 Key值比较，并返回所有相关函数名。请你按如下步骤分析：1.查看历史过程。2.检查UDS 27过程是否完整。3.返回覆盖UDS 27过程的所有函数名",
                   "当前目标：扫描UDS27代码中的逻辑漏洞。主要扫描三类漏洞：1.信息泄露漏洞（包括硬编码的预共享密钥等敏感信息）；2.算法缺陷（包括Seed2Key算法缺乏非线性算法、预共享密钥长度过短）；3.认证挑战逻辑缺陷（包括随机性不足、缺乏防重放攻击保护）。请分析当前代码，识别这些漏洞，并给出需要进一步分析的函数或变量。对于硬编码密钥，需要实际查看全局变量内容确认。"                   ]

                   #"当前目标：逆向当前Seed2Key代码，确认安全密钥是否以硬编码形式存在。【备注】：Seed2Key代码是UDS诊断27服务核心,將Seed结合一个或多个安全密钥進行一些运算，最终计算出Key值。请你按如下步骤分析：1.請你分析函数逻辑。2.请你明确Seed，安全密钥，Key分別是哪些變量。3.为了確定安全密鑰是否以硬編碼形式直接儲存在固件中，给出你希望进一步分析哪个变量或者函数（可选操作：1.得到目标函数的反编译内容（即.获得目标函数内容，在type中输入get_decompilation）。2.得到某個全局变量的内容（即.获得全局变量的内容，在type中输入get_global_var）。4.判断是否完成目标,然后将当前分析过的所有函数的函数名重新命名以总结其功能。"                   ]
                            # 当前目标：确认rand函数。备注：rand是随机函数。请你按如下步骤分析：1.先分析整个函数的逻辑。2.给出你希望进一步分析的某个函数（可选操作：1.得到目标函数的反编译内容（即.获得目标函数内容，在type中输入get_decompilation）。2.得到目标函数的交叉引用（即.获得哪些函数调用了目标函数，在type中输入get_cross_references））。3.判断是否完成目标。

    while(1):  
        print("----------------------------------------------------------------------------------------------------------")
        #print(code)s
        #print("----------------------------------------------------------------------------------------------------------")
        user_input = askString("用户输入", "请输入字节数据:","请填写:")
        #response = LLMs_explain_deepseek(client_deepseek, code, LLMs_Object[Index],json_structure[Index],user_input)#LLMs_explain(client_qwen, code, LLMs_Object[Index],json_structure[Index],user_input)
        old_commend = join_strings(commend_list)
        # 在提示词中携带当前 seed 信息
        seed_hint = f"当前推断的seed变量为: {current_seed}" if current_seed else ""
        
        # 第5阶段特殊处理：加载uds27_overview.json作为输入
        if Index == 4:
            overview_data = load_uds27_overview()
            if overview_data:
                overview_hint = f"\n第4阶段结果: {json.dumps(overview_data, ensure_ascii=False)}"
                code = code + overview_hint
        
        # 防止索引越界
        if Index >= len(LLMs_Object) or Index >= len(json_structure):
            print(f"[ERROR] Index {Index} 超出范围，LLMs_Object长度: {len(LLMs_Object)}, json_structure长度: {len(json_structure)}")
            break
        response = LLMs_explain(get_llm_client(), code + "\n" + seed_hint, LLMs_Object[Index],json_structure[Index],user_input,old_commend)

        function_list = []
        
       # print("----------------------------------------------------------------------------------------------------------")
        #print(response)
        print("----------------------------------------------------------------------------------------------------------")
        if response["是否完成目标"]["result"] == "no":
            # 首目标：若判定为 no，则停止当前 code 的探索，切换到下一个 code
            if Index == 0:
                if code_queue:
                    next_item = code_queue.pop(0)
                    code = next_item.get("code")
                    current_seed = next_item.get("seed")
                    print(f"[NEXT] 切换到下一个code: {next_item.get('function')}")
                    continue
                else:
                    print("[DONE] 首目标未命中且无更多code，进入下一个目标阶段")
                    Index = 1
                    continue
            # 第三目标：限制循环次数，超过5次直接跳到下一个目标
            elif Index == 2:
                loop_count += 1
                if loop_count >= 5:
                    print(f"[LIMIT] 第三目标循环次数已达上限({loop_count})，强制完成并进入下一目标")
                    Index = 3
                    loop_count = 0  # 重置计数器
                    continue
            # 第五目标：限制循环次数，超过5次直接跳到下一个目标
            elif Index == 4:
                loop_count += 1
                if loop_count >= 5:
                    print(f"[LIMIT] 第五目标循环次数已达上限({loop_count})，强制完成并进入下一目标")
                    Index = 5
                    loop_count = 0  # 重置计数器
                    continue
            if response["进一步请求"]["type"] == "get_cross_references":
                commend_list.append(str(response["进一步请求"]))
                function_name = response["进一步请求"].get("target_function_name")
                if function_name is None:
                    function_name = response["进一步请求"].get("target_fuc_or_val")
                if isinstance(function_name, list):
                    for item in function_name:
                        if 'DAT' not in item:
                            refs = print_cross_references(item,"FUN")

                        else:
                            #先去嘗試直接get X_ref，所有
                            refs = print_cross_references(item,"DAT")
                        if refs:
                            for ref in refs:
                                function_list.append(get_decompilation(ref))
                            #function_list.append(code)
                            code = join_strings(item)
                        else:
                            function_list.append(function_name+"没有任何函数调用")
                            #function_list.append(code)
                            code = join_strings(item)
                    
                elif isinstance(function_name, str):
                    #---------------------------------------------------------------------------------------------------------
                    if 'DAT' not in function_name:
                        refs = print_cross_references(function_name,"FUN")

                    else:
                        #先去嘗試直接get X_ref，所有
                        refs = print_cross_references(function_name,"DAT")
                    if refs:
                        for ref in refs:
                            function_list.append(get_decompilation(ref))
                        #function_list.append(code)
                        code = join_strings(function_list)
                    else:
                        function_list.append(function_name+"没有任何函数调用")
                        #function_list.append(code)
                        code = join_strings(function_list)
                    #---------------------------------------------------------------------------------------------------------
                
                
            if response["进一步请求"]["type"] == "get_decompilation":
                commend_list.append(str(response["进一步请求"]))
                function_name = response["进一步请求"].get("target_function_name")
                if function_name is None:
                    function_name = response["进一步请求"].get("target_fuc_or_val")
                def _handle_decomp_target(name):
                    if not name or not isinstance(name, str):
                        return
                    # DAT_ 等全局符号不是函数，禁止反编译，直接给出提示，要求改用其他方法
                    if name.startswith("DAT_"):
                        function_list.append(f"[INVALID] 目标 {name} 不是函数，无法反编译。请改用 get_global_var 或 get_cross_references。")
                        return
                    # 非函数名也直接报错提示
                    func_obj = getFunction(name)
                    if not func_obj:
                        function_list.append(f"[NOT_FOUND] 未找到函数: {name}")
                        return
                    res = get_decompilation(name)
                    if res:
                        function_list.append(res)
                    else:
                        function_list.append(f"[DECOMP_FAIL] 反编译失败: {name}")

                if isinstance(function_name, list):
                    for item in function_name:
                        _handle_decomp_target(item)
                else:
                    _handle_decomp_target(function_name)
                code = join_strings(function_list)
            if response["进一步请求"]["type"] == "get_global_var":
                print('xxxxxxxxxxxx')
                symbol_name = response["进一步请求"].get("target_function_name")
                if symbol_name is None:
                    symbol_name = response["进一步请求"].get("target_fuc_or_val")
                data =[]
                if isinstance(symbol_name, list):
                    for item in symbol_name:
                        data.append(f"{item}是{get_global_variable_data(item)}")
                else:
                    data.append(f"{symbol_name}是{get_global_variable_data(symbol_name)}")
                code = join_strings(data)

            # 处理目标4：UDS27功能是否齐全的总览与保存
            if response.get("目标") and "功能是否齐全" in response.get("目标"):
                try:
                    status_flag = response.get("是否完成目标", {}).get("result")
                    feature_map = response.get("功能判定", {}) or {}
                    related_funcs = response.get("相关函数", {}) or {}
                    output = {
                        "goal": response.get("目标"),
                        "complete": True if status_flag == "yes" else False,
                        "missing_features": [],
                        "functions": {}
                    }
                    missing = []
                    categories = ["seed_generate", "seed_split", "seed2key", "key_compare"]
                    all_codes = []
                    for cat in categories:
                        val = feature_map.get(cat, "no")
                        if str(val).lower() != "yes":
                            missing.append(cat)
                        names = related_funcs.get(cat, [])
                        items = []
                        if isinstance(names, list):
                            for nm in names:
                                try:
                                    c = get_decompilation(nm)
                                except Exception:
                                    c = None
                                items.append({"name": nm, "code": c})
                                if c:
                                    all_codes.append(c)
                        output["functions"][cat] = items
                    output["missing_features"] = missing
                    log_separator("阶段4: uds27_overview")
                    with open(os.path.join(LOG_DIR, "uds27_overview.json"), "w", encoding="utf-8") as f:
                        json.dump(output, f, ensure_ascii=False, indent=2)
                    write_stage_log(4, output)
                    if status_flag == "yes":
                        print("UDS27功能齐全。")
                    else:
                        print("UDS27功能不全，缺失: {}".format(", ".join(missing)))
                    concatenated = "\n\n".join(all_codes) if all_codes else ""
                    if concatenated:
                        print(concatenated)
                    code = concatenated if concatenated else code
                except Exception as e:
                    print("生成UDS27总览失败: {}".format(e))

        elif response["是否完成目标"]["result"] == "yes":
            #Chat_history.append({"role": "user", "content": response["是否完成目标"]["reason"]})
            Index = Index + 1
            loop_count = 0  # 重置计数器
            # 如果还有队列中的命中函数，切换到下一条继续主循环
            if code_queue:
                next_item = code_queue.pop(0)
                code = next_item.get("code")
                current_seed = next_item.get("seed")
            feature_lis = response["是否完成目标"].get("符合的特征")
            if feature_lis is not None:
                if len(feature_lis) >1:
                    Index = Index+0
            # 处理目标4：UDS27功能是否齐全的总览与保存（功能齐全场景）
            if response.get("目标") and "功能是否齐全" in response.get("目标"):
                try:
                    feature_map = response.get("功能判定", {}) or {}
                    related_funcs = response.get("相关函数", {}) or {}
                    output = {
                        "goal": response.get("目标"),
                        "complete": True,
                        "missing_features": [],
                        "functions": {}
                    }
                    categories = ["seed_generate", "seed_split", "seed2key", "key_compare"]
                    all_codes = []
                    for cat in categories:
                        names = related_funcs.get(cat, [])
                        items = []
                        if isinstance(names, list):
                            for nm in names:
                                try:
                                    c = get_decompilation(nm)
                                except Exception:
                                    c = None
                                items.append({"name": nm, "code": c})
                                if c:
                                    all_codes.append(c)
                        output["functions"][cat] = items
                    log_separator("阶段4: uds27_overview")
                    with open(os.path.join(LOG_DIR, "uds27_overview.json"), "w", encoding="utf-8") as f:
                        json.dump(output, f, ensure_ascii=False, indent=2)
                    write_stage_log(4, output)
                    print("UDS27功能齐全。")
                    concatenated = "\n\n".join(all_codes) if all_codes else ""
                    if concatenated:
                        print(concatenated)
                    code = concatenated if concatenated else code
                except Exception as e:
                    print("生成UDS27总览失败: {}".format(e))

            # 处理目标5：逻辑漏洞扫描与保存
            if response.get("目标") and "逻辑漏洞" in response.get("目标"):
                try:
                    vulnerability_analysis = response.get("漏洞分析", {}) or {}
                    output = {
                        "goal": response.get("目标"),
                        "vulnerabilities": vulnerability_analysis,
                        "timestamp": datetime.now().isoformat()
                    }
                    log_separator("阶段5: vulnerability_scan")
                    with open(os.path.join(LOG_DIR, "vulnerability_scan.json"), "w", encoding="utf-8") as f:
                        json.dump(output, f, ensure_ascii=False, indent=2)
                    write_stage_log(5, output)
                    print("漏洞扫描结果已保存到 vulnerability_scan.json")
                except Exception as e:
                    print("生成漏洞扫描结果失败: {}".format(e))

            #--------------------------------------------重命名------------------------------#
            rename_lis = response["是否完成目标"].get("rename")
            if rename_lis is not None:
                function_list = []
                for rename_item in rename_lis:
                    success, message = rename_function(rename_item["old_fun_name"], rename_item["new_fun_name"])
                    function_list.append(get_decompilation(rename_item["new_fun_name"]))
                code = join_strings(function_list)
         
            
            if response.get("目标") == "找到生成随机数的相关函数":
                flag = 0
                rename_lis = response["是否完成目标"].get("rename")
                rename_item = rename_lis[0]
            
                refs = print_cross_references(rename_item["new_fun_name"], "FUN")
            
                if refs:
                    # 定义一个辅助函数来递归检查，并限制递归深度
                    def check_refs(refs_list, matching_funcs, depth=0, previous_ref=None):
                        if depth >= 20:  # 达到最大递归深度，停止递归
                            return None
                        for ref in refs_list:
                            if ref in matching_funcs:
                                print(f"命中{ref}")
                                return f"其中{previous_ref if previous_ref else '未知'}用于生成seed，{ref}和Seed2Key函数有关" + get_decompilation(ref)
                            else:
                                #这块不够深
                                call_refs = get_called_functions(ref)
                                print(call_refs)
                                for call_ref in call_refs:
                                    if call_ref in matching_funcs:
                                        print(f"命中{call_ref}")
                                        return f"其中{previous_ref if previous_ref else '未知'}用于生成seed, {call_ref}和Seed2Key函数有关" +get_decompilation(ref) + get_decompilation(call_ref)
                                sub_refs = print_cross_references(ref, "FUN")
                                if sub_refs:
                                    result = check_refs(sub_refs, matching_funcs, depth + 1, ref)  # 传递当前ref作为下一个递归的previous_ref
                                    if result:
                                        return result
                        return None
            
                    result = check_refs(refs, matching_functions)
                    if result:
                        code = result
                        flag = 1
                    else:
                        code = "未找到相关函数"
           
            elif response.get("目标") =="逆向UDS协议27子服务中seed传递确定Seed变量":
                seed_relationships = response.get("seed变量传递关系")
                if seed_relationships is not None:
                    try:
                        leaf_nodes, not_leaf_nodes = find_leaf_nodes(seed_relationships)
                        print("非叶节点:", not_leaf_nodes)
                        relationships_2 = find_variable_relationships(code, not_leaf_nodes[0])
                        print("关联关系:", relationships_2)
                        leaf_nodes,not_leaf_nodes = find_leaf_nodes(relationships_2)
                        print("叶节点优化:", leaf_nodes)
                        filtered_and_grouped_nodes = filter_and_group_leaf_nodes(leaf_nodes)
                        print("过滤并聚合后的叶节点:", filtered_and_grouped_nodes)
                        code = "找到Seed2Key的最关键在于"+join_strings(filtered_and_grouped_nodes)+"请你对他进行交叉引用"+code
                    except Exception as e:
                        print("当前函数反编译不规范，造成污点分析错误")
    
