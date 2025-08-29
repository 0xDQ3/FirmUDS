from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import Reference
from ghidra.framework.model import DomainFile
from ghidra.program.model.listing import Program
from ghidra.util import Msg
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
import time

Chat_history = []

# Ghidra Python Script to Rename a Function
# @category: Example
# @author: Your Name

from ghidra.program.model.symbol import SourceType

# Logging functionality (writes to logs/ in the same directory as the script)
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

# ==================== LLM Client Configuration ====================
# Configure all LLM client API keys, URLs, and model names here
LLM_CONFIG = {
    "qwen": {
        "api_key": "sk-xxxx",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-max-2025-01-25"
    },
    "moonshot": {
        "api_key": "sk-xxxx",
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-32k"
    },
    "deepseek": {
        "api_key": "sk-xxxx",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v3"
    }
}

# Default LLM client (can be switched here)
DEFAULT_LLM = "qwen"

def get_llm_client(client_name=None):
    """
    Get an LLM client instance
    :param client_name: Name of the client, e.g., "qwen", "moonshot", "deepseek"
    :return: OpenAI client instance
    """
    if client_name is None:
        client_name = DEFAULT_LLM
    
    if client_name not in LLM_CONFIG:
        print(f"[WARNING] Client configuration not found: {client_name}, using default client: {DEFAULT_LLM}")
        client_name = DEFAULT_LLM
    
    config = LLM_CONFIG[client_name]
    return OpenAI(
        api_key=config["api_key"],
        base_url=config["base_url"]
    )

def get_llm_model(client_name=None):
    """
    Get the LLM model name
    :param client_name: Name of the client
    :return: Model name string
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
    Input a function name and return its decompiled code
    """
    program = currentProgram()
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    func = getFunction(func_name)
    if not func:
        print(f"Function not found: {func_name}")
        return

    res = decompiler.decompileFunction(func, 0, monitor())
    decompiled = res.getDecompiledFunction()
    if decompiled:
        print("Decompiled Code:")
        print(decompiled.getC())
        return str(decompiled.getC())
    else:
        print("Decompilation failed.")

def getFunction(func_name):
    """
    Get the function object by function name.
    """
    start_time = time.time()
    program = currentProgram()
    funcs = program.getListing().getFunctions(True)
    for func in funcs:
        if func.getName() == func_name:
            elapsed = time.time() - start_time
            write_log(f"[TIMING] getFunction('{func_name}') took {elapsed:.4f}s")
            return func
    elapsed = time.time() - start_time
    write_log(f"[TIMING] getFunction('{func_name}') took {elapsed:.4f}s (not found)")
    return None

def get_cross_references(func_name):
    """
    Input a function name and return a list of cross-references where the function is called by other functions.
    """
    program = currentProgram()
    func = getFunction(func_name)
    if not func:
        print(f"Function not found: {func_name}")
        return []

    references = []
    addr = func.getEntryPoint()
    for ref in program.getReferenceManager().getReferencesTo(addr):
        if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL or ref.getReferenceType() == RefType.CONDITIONAL_CALL:
            from_func = program.getListing().getFunctionContaining(ref.getFromAddress())
            if from_func:
                references.append(from_func.getName())
    return references

def print_cross_references(func_name, type):
    start_time = time.time()
    if type == "FUN":
        refs = get_cross_references(func_name)
    else:
        results = find_symbol_references(func_name)
        refs = []
        if results:
            for addr, name in sorted(set(results)):  # Remove duplicates
                refs.append("{}".format(name))
            refs = set(refs)
        else:
            refs = None

    elapsed = time.time() - start_time
    write_log(f"[TIMING] print_cross_references('{func_name}', '{type}') took {elapsed:.4f}s, found {len(refs) if refs else 0} references")

    if refs:
        print(f"Cross-references for function '{func_name}':")
        for ref in refs:
            print(ref)
        return refs
    else:
        print(f"No cross-references found for function '{func_name}'.")
        return None

def LLMs_explain(client, code, LLMs_Object, json_structure, input, old_commend):
    global Chat_history
    sys_content = f"You are a decompilation analysis expert, particularly knowledgeable about Ghidra and automotive UDS-related functions. Avoid getting stuck in logical loops! The previously executed requests are {old_commend}, do not repeat [further requests]. Additionally, {LLMs_Object}"
    
    user_meag = f"Provided code: {code}. Please analyze it. {input} Please output in JSON structure ```json{json_structure}```"
    user_input = {"role": "user", "content": user_meag}
    Chat_history.append(user_input)

    try:
        completion = client.chat.completions.create(
            model=get_llm_model(),
            messages=[{"role": "system", "content": sys_content}] + Chat_history
        )
        GPT_text = completion.choices[0].message.content
        print(GPT_text)
        Chat_history.append({"role": "assistant", "content": GPT_text})
        json_pattern = r"```json(.*?)```"
        match = re.search(json_pattern, GPT_text, re.DOTALL)
        if match:
            json_str = match.group(1).strip().replace("\n", " ").replace('\\', '\\\\')
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
            # Save error context
            save_llm_error_state({
                "phase": "LLMs_explain",
                "sys_content": sys_content,
                "Chat_history": Chat_history,
                "raw_output": GPT_text,
                "json_structure": json_structure
            })
            print("[LLM_PARSE_ERROR] Error context saved for recovery.")
            # Return a clear placeholder result to avoid crashing
            return {"is_goal_achieved": {"result": "no", "reason": "LLM response parsing failed"}}
        return json_data
    except Exception as e:
        # Save error context
        save_llm_error_state({
            "phase": "LLMs_explain_exception",
            "error": str(e),
            "sys_content": sys_content,
            "Chat_history": Chat_history,
            "json_structure": json_structure
        })
        print(f"[LLM_CALL_ERROR] {e}, error context saved for recovery.")
        return {"is_goal_achieved": {"result": "no", "reason": "LLM call exception"}}

def LLMs_explain_deepseek(client, code, LLMs_Object, json_structure, input):
    global Chat_history
    sys_content = f"You are a decompilation analysis expert, particularly knowledgeable about Ghidra and automotive UDS-related functions. Avoid getting stuck in logical loops! Do not repeat [further requests]. Additionally, {LLMs_Object} Please output in JSON structure ```json{json_structure}```"
    
    user_meag = f"Provided [current function]: {code}. Please analyze it. {input}"

    Chat_history.append(HumanMessage(content=user_meag))
    messages = [SystemMessage(content=sys_content)] + Chat_history

    GPT_text = client.invoke(messages).content
    print(GPT_text)
    Chat_history.append(HumanMessage(content=GPT_text))
    json_pattern = r"```json(.*?)```"
    match = re.search(json_pattern, GPT_text, re.DOTALL)
    if match:
        json_str = match.group(1).strip().replace("\n", " ").replace('\\', '\\\\').replace(":", ":").replace("'", '"').replace("'", '"').replace('"', '"').replace('"', '"')
        try:
            json_data = json.loads(json_str)
        except json.JSONDecodeError:
            print("Invalid JSON format.")
    else:
        json_data = json.loads(GPT_text.replace("\n", " "))
    return json_data

def find_leaf_nodes(relationships):
    # Create a set to store all nodes
    all_nodes = set()
    # Create a set to store non-leaf nodes (i.e., nodes with outgoing edges)
    non_leaf_nodes = set()
    
    # Iterate through the relationship list
    for relation in relationships:
        # Split the relationship to get source and target nodes
        source, target = relation.split("->")
        # Add source and target nodes to the all nodes set
        source = source.replace(" ", "")
        target = target.replace(" ", "")
        all_nodes.add(source)
        all_nodes.add(target)
        # Add source node to non-leaf nodes set
        non_leaf_nodes.add(source)
    
    # Leaf nodes are those in all_nodes but not in non_leaf_nodes
    leaf_nodes = all_nodes - non_leaf_nodes
    
    return list(leaf_nodes), list(non_leaf_nodes)

def filter_and_group_leaf_nodes(leaf_nodes):
    # Categorize: variables starting with DAT_ and functions starting with FUN_
    dat_nodes = sorted([node for node in leaf_nodes if node.startswith("DAT_")], key=lambda x: int(x.split("_")[1], 16))
    fun_nodes = [node for node in leaf_nodes if node.startswith("FUN_")]

    # Store the final result
    result = []

    # Handle DAT_ variables
    if dat_nodes:
        groups = []
        current_group = [dat_nodes[0]]

        for i in range(1, len(dat_nodes)):
            # Extract the numeric part and check if consecutive
            current_value = int(dat_nodes[i].split("_")[1], 16)
            previous_value = int(dat_nodes[i - 1].split("_")[1], 16)

            if current_value == previous_value + 1:
                current_group.append(dat_nodes[i])
            else:
                groups.append(current_group)
                current_group = [dat_nodes[i]]
        
        # Add the last group
        groups.append(current_group)

        # Merge consecutive groups into arrays, keep non-consecutive ones separate
        for group in groups:
            if len(group) > 1:
                # Merge into an array
                base_name = min(group)
                result.append(f"{base_name}[]")
            else:
                # Keep separate
                result.extend(group)

    # Add FUN_ functions
    result.extend(fun_nodes)

    return result

def find_variable_relationships(code, target_var):
    seed_relationships = []
    relationships = {}
    queue = [target_var]
    visited = set()

    lines = code.split('\n')
    # Preprocess to extract all possible variable relationships
    for line in lines:
        line = line.strip()
        # Match assignment statements, e.g., uVar1 = DAT_7001365c
        if '=' in line:
            parts = line.split('=', 1)
            if len(parts) >= 2:
                left = parts[0].strip()
                right = parts[1].strip().split(';')[0].strip()  # Remove possible semicolon
                # Extract variables on the right
                right_vars = re.findall(r'\b(\w+)\b', right)
                # Save relationships between left and right variables
                for var in right_vars:
                    if var not in relationships:
                        relationships[var] = set()
                    relationships[var].add(left)
    
    # BFS to find all variables related to the target variable
    while queue:
        current_var = queue.pop(0)
        if current_var not in visited:
            visited.add(current_var)
            # Find all target variables (i.e., variables being assigned to)
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
    Read all machine code between two addresses.

    Parameters:
        start_addr (str): Start address (e.g., "0x1000")
        end_addr (str): End address (e.g., "0x2000")

    Returns:
        list: List of machine code bytes between the two addresses
    """
    # Convert string addresses to Ghidra Address objects
    start_address = start_addr
    end_address = end_addr

    # Create address range
    addr_set = AddressSet(start_address, end_address)

    # Get code units of the current program
    code_units = currentProgram().getListing().getCodeUnits(addr_set, True)

    machine_code = []
    for code_unit in code_units:
        # Get machine code bytes of the code unit
        bytes = code_unit.getBytes()
        machine_code.extend(bytes)

    return machine_code

def get_global_variable_data(symbol_name):
    target_symbol = get_target_symbol(symbol_name)
    if not target_symbol:
        print(f"[ERROR] Symbol not found: {symbol_name}")
        return None
    dat_symbols = get_sorted_dat_symbols()
    try:
        current_index = dat_symbols.index(target_symbol)
    except ValueError:
        print(f"[ERROR] Symbol {symbol_name} not in DAT_ symbol list")
        return None
    if current_index + 1 >= len(dat_symbols):
        print("[ERROR] No subsequent DAT_ symbol")
        return None
    start_addr = target_symbol.getAddress()
    next_symbol = dat_symbols[current_index + 1]
    end_addr = next_symbol.getAddress()
    if end_addr <= start_addr:
        print("[ERROR] Next symbol address must be greater than current symbol address")
        return None
    data = read_machine_code_between_addresses(start_addr, end_addr)
    if len(data) == 0:
        return None
    else:
        print(f"Data from {start_addr} to {end_addr} (total {len(data)} bytes):")
        # Display in hexadecimal groups
        hex_str = ' '.join(f"{b & 0xFF:02X}" for b in data)
        print(hex_str)
        return hex_str

def get_called_functions(function_name):
    """
    Input a function name and return a list of all function names called by it
    :param function_name: The function name to query
    :return: List of called function names (may include duplicates)
    """
    program = currentProgram()
    function_manager = program.getFunctionManager()
    
    # Find the target function globally
    target_func = None
    for func in function_manager.getFunctions(True):  # True for forward traversal
        if func.getName() == function_name:
            target_func = func
            break
    
    if not target_func:
        print(f"Function not found: {function_name}")
        return []
    
    # Get the set of called functions
    called_functions = target_func.getCalledFunctions(getMonitor())
    
    # Extract function names and return
    return [func.getName() for func in called_functions]

def find_symbol_references(symbol_name):
    program = currentProgram()
    symbol_table = program.getSymbolTable()
    symbols = list(symbol_table.getSymbols(symbol_name))
    
    if not symbols:
        print(f"Symbol not found: {symbol_name}")
        return []
    
    symbol = symbols[0]
    symbol_addr = symbol.getAddress()
    target_addr = symbol_addr.getOffset()  # Get address as a numeric value
    target_addr = target_addr & 0xFFFF
    print(f"target_addr {hex(target_addr)}")
    # Method 1: Get explicit references via reference manager
    ref_manager = program.getReferenceManager()
    explicit_refs = ref_manager.getReferencesTo(symbol_addr)
    
    # Method 2: Scan all instructions for immediate operands
    implicit_refs = []
    mem = program.getMemory()
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        
        addr_set = AddressSet(block.getStart(), block.getEnd())
        monitor = ConsoleTaskMonitor()
        for instr in program.getListing().getInstructions(addr_set, True):
            operands = instr.getOpObjects(1)  # Get all operands
            for op in operands:
                if hasattr(op, 'getValue'):
                    op_value = op.getValue()
                    if op_value == target_addr:
                        implicit_refs.append(instr.getAddress())
    
    # Merge results
    results = []
    # Handle explicit references
    for ref in explicit_refs:
        from_addr = ref.getFromAddress()
        func = getFunctionContaining(from_addr)
        results.append((from_addr, func.getName() if func else "unknown_function"))
    
    # Handle implicit references (immediate values)
    for addr in implicit_refs:
        func = getFunctionContaining(addr)
        results.append((addr, func.getName() if func else "unknown_function"))
   
    return results

def join_strings(function_list):
    """
    Join list elements into a string separated by newlines

    :param function_list: List containing string elements
    :return: Concatenated string
    """
    # Filter out None to ensure safe concatenation
    safe_list = [s for s in function_list if isinstance(s, str)]
    return '\n'.join(safe_list)

def _is_ud27_split_or_combine_pattern(decompiled_code):
    """
    More precise matching for common UDS27 4-byte split/combine patterns to ensure typical cases are hit:
    1) Split:
       *param[i] = (char)((uint)X >> {0x18,0x10,0x8});
       param[j] = (char)X;  // Direct low byte assignment
    2) Combine:
       U = (uint)param[3] | (uint)*param << 0x18 | (uint)param[1] << 0x10 | (uint)param[2] << 8;

    Note: Use regex to detect key shifts and array indexing/bitwise operations combinations.
    """
    try:
        import re as _re
        text = decompiled_code

        # Typical split: Three right shifts 0x18/0x10/0x8 with (char) and array write param_x[...]
        has_split_shifts = (('>> 0x18' in text) and ('>> 0x10' in text) and ('>> 0x8' in text))
        has_char_cast = '(char)' in text
        has_array_write = _re.search(r"\b\w+\s*\[\s*[0-3]\s*\]\s*=", text) is not None or ('*param_' in text and '=' in text)

        split_like = has_split_shifts and has_char_cast and has_array_write

        # Typical combine: Four OR operations with << 0x18, << 0x10, << 0x8 and array read param[0..3] or *param
        has_or_ops = text.count('|') >= 3
        has_left_shifts = ('<< 0x18' in text) and ('<< 0x10' in text) and ('<< 0x8' in text)
        has_array_read = _re.search(r"\b\w+\s*\[\s*[0-3]\s*\]", text) is not None or '*param' in text

        combine_like = has_or_ops and has_left_shifts and has_array_read

        return bool(split_like or combine_like)
    except Exception:
        return False

def Looking_for_suspicious_UDS27():
    # Skip decompilation for overly large functions (by address span) to avoid timeouts
    MAX_DECOMP_FUNC_SIZE = 4000
    stage_start_time = time.time()
    write_log("[TIMING] Stage 1: UDS27 feature function identification started")
    
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

        # Check size before decompilation (by address span from min to max)
        try:
            body = function.getBody()
            min_addr = body.getMinAddress()
            max_addr = body.getMaxAddress()
            if min_addr is not None and max_addr is not None:
                span = max_addr.getOffset() - min_addr.getOffset()
                if span >= MAX_DECOMP_FUNC_SIZE:
                    print(f"[SKIP_FUNC] {function.getName()} size={span} >= {MAX_DECOMP_FUNC_SIZE}, skip decompile")
                    continue
        except Exception:
            # Fallback: If size cannot be calculated, do not skip
            pass

        # Decompile the function
        decompile_result = decompiler.decompileFunction(function, 60, monitor)

        if not decompile_result.decompileCompleted():
            print(f"Cannot decompile function: {function.getName()}")
            continue

        # Get the decompiled code
        decompiled_code = decompile_result.getDecompiledFunction().getC()

        # Check for UDS27 byte manipulation patterns
        has_shift_18 = ('<< 0x18' in decompiled_code) or ('>> 0x18' in decompiled_code)
        has_shift_10 = ('<< 0x10' in decompiled_code) or ('>> 0x10' in decompiled_code)

        # Heuristic A: Original heuristic
        heuristic_match = False
        if has_shift_18 and has_shift_10:
            byte_manipulation_indicators = [
                'uint', 'char', 'byte', 'DAT_', '|', '^', '&', '[', ']'
            ]
            indicator_count = sum(1 for indicator in byte_manipulation_indicators if indicator in decompiled_code)
            has_array_ops = '[' in decompiled_code and ']' in decompiled_code
            has_bitwise_ops = '|' in decompiled_code or '^' in decompiled_code or '&' in decompiled_code
            heuristic_match = indicator_count >= 2 and (has_array_ops or has_bitwise_ops)

        # Heuristic B: Precise pattern matching (ensures typical cases hit)
        precise_match = _is_ud27_split_or_combine_pattern(decompiled_code)

        if heuristic_match or precise_match:
            matching_functions.append(function.getName())
            # Detect specific shift operations (for logging)
            left_shift_18 = '<< 0x18' in decompiled_code
            left_shift_10 = '<< 0x10' in decompiled_code
            right_shift_18 = '>> 0x18' in decompiled_code
            right_shift_10 = '>> 0x10' in decompiled_code

            shift_types = []
            if left_shift_18: shift_types.append("<<0x18")
            if left_shift_10: shift_types.append("<<0x10")
            if right_shift_18: shift_types.append(">>0x18")
            if right_shift_10: shift_types.append(">>0x10")

            has_array_ops = '[' in decompiled_code and ']' in decompiled_code
            has_bitwise_ops = '|' in decompiled_code or '^' in decompiled_code or '&' in decompiled_code
            indicator_count = sum(1 for indicator in ['uint','char','byte','DAT_','|','^','&','[',']'] if indicator in decompiled_code)

            print(f"[UDS27_MATCH] {function.getName()}: shift_ops={shift_types}, "
                  f"has_array_ops={has_array_ops}, has_bitwise_ops={has_bitwise_ops}, "
                  f"indicators={indicator_count}, precise={precise_match}")

    decompiler.dispose()

    stage_elapsed = time.time() - stage_start_time
    write_log(f"[TIMING] Stage 1: UDS27 feature function identification completed, time taken {stage_elapsed:.2f}s, found {len(matching_functions)} matching functions")

    if matching_functions:
        print("Functions whose pseudocode contains 0x18 and 0x10 shift operations (left or right):")
        for func_name in matching_functions:
            print(f" - {func_name}")
    else:
        print("No functions containing 0x18 and 0x10 shift operations were found.")
    return matching_functions

def merge_tuples(input_list):
    # Create a dictionary with the last element of each tuple as the key
    result_dict = {}
    
    for tup in input_list:
        # Get the last element of the tuple as the key
        key = tup[-1]
        # Store the other elements of the tuple as the value
        result_dict[key] = tup[:-1]
    
    # Extract dictionary values to form a new list
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
    # Record script start time
    script_start_time = time.time()
    write_log(f"[TIMING] Script execution started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Attempt to resume from previous LLM error state at startup
    resume_state = load_llm_error_state()
    if resume_state:
        try:
            # Try to restore Chat history to continue the context
            prev_chat = resume_state.get("Chat_history")
            if isinstance(prev_chat, list):
                Chat_history = prev_chat
                print("[RESUME] Chat history restored, continuing execution.")
        except Exception as e:
            print(f"[RESUME_FAIL] {e}")
    
    # Stage 1: Find UDS27 feature functions
    log_separator("Stage 1: matching_functions")
    stage1_start = time.time()
    matching_functions = Looking_for_suspicious_UDS27()
    stage1_elapsed = time.time() - stage1_start
    write_log(f"[TIMING] Stage 1 total time: {stage1_elapsed:.2f}s")
    print(matching_functions)
    write_stage_log(1, {"matching_functions": matching_functions, "stage_time": stage1_elapsed})

    # Stage 2: Find RAND generator trigger
    function_name_list = []  # Candidate RAND functions
    rand_input_str = askString("Input suspected random functions for binary similarity analysis:", "Example: 'FUN_aaa FUN_bbb FUN_ccc'")
    rand_input_lis = rand_input_str.split()
    _dat_refs = print_cross_references("DAT_f0001010", "DAT")
    base_set = set(rand_input_lis)
    if _dat_refs:
        try:
            rand_refs = set(_dat_refs).union(base_set)
        except Exception:
            rand_refs = base_set
    else:
        rand_refs = base_set
    # Currently, only tc39x can use this register
    # Additional suspected RAND functions can be supplemented
    # LCG + Binary similarity comparison
    for rand_ref in rand_refs:
        refs = print_cross_references(rand_ref, "FUN")
        if refs:
            # Define a helper function to recursively check with depth limit
            def check_refs(refs_list, matching_funcs, depth=0, previous_ref=None):
                if depth >= 20:  # Stop recursion at max depth
                    return None
                for ref in refs_list:
                    if ref in matching_funcs:
                        desc = f"Among which {previous_ref if previous_ref else 'unknown'} is used to generate seed, {ref} is related to Seed2Key function" + get_decompilation(ref)
                        function_name_list.append((desc, previous_ref, rand_ref, ref))
                        return desc
                    else:
                        call_refs = get_called_functions(ref)
                        for call_ref in call_refs:
                            if call_ref in matching_funcs:
                                desc = f"Among which {previous_ref if previous_ref else 'unknown'} is used to generate seed, {call_ref} is related to Seed2Key function" + get_decompilation(ref) + get_decompilation(call_ref)
                                function_name_list.append((desc, ref, previous_ref, rand_ref, call_ref))
                                return desc
                        sub_refs = print_cross_references(ref, "FUN")
                        if sub_refs:
                            result = check_refs(sub_refs, matching_funcs, depth + 1, ref)  # Pass current ref as previous_ref for next recursion
                            if result:
                                return result
                return None
            result = check_refs(refs, matching_functions)
            if result:
                code = result
                flag = 1
            else:
                code = "No related function found"
    
    # Build seed map before merging to preserve original chain previous_ref
    seed_map_pre = build_seed_map(function_name_list)
    # Merge tuples
    function_name_list = merge_tuples(function_name_list)
    log_separator("Stage 2: ask_index")
    write_log("[TIMING] Stage 2: Random number generator association analysis started")
    stage2_start = time.time()

    # Concurrent automatic analysis: Decompile all candidate functions in parallel and use LLM to determine UDS27 features
    ask_index = [name[-1] for i, name in enumerate(function_name_list[0:])]
    
    # If ask_index is empty, use matching_functions as fallback
    if not ask_index:
        ask_index = matching_functions
        print(f"[FALLBACK] ask_index is empty, using matching_functions as fallback: {ask_index}")
    
    # Use unified LLM client configuration
    client_qwen = get_llm_client("qwen")
    client_moonshot = get_llm_client("moonshot")

    # Stage 2 timing ends: From random number analysis to ask_index construction completion
    stage2_elapsed = time.time() - stage2_start
    write_log(f"[TIMING] Stage 2 total time: {stage2_elapsed:.2f}s, ask_index length={len(ask_index)}")
    write_stage_log(2, {"ask_index": ask_index, "ask_index_length": len(ask_index), "stage_time": stage2_elapsed})

    def _parse_llm_json(GPT_text):
        json_pattern = r"```json(.*?)```"
        match = re.search(json_pattern, GPT_text, re.DOTALL)
        if match:
            json_str = match.group(1).strip().replace("\n", " ").replace('\\', '\\\\')
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
            "You are a decompilation analysis expert, particularly knowledgeable about Ghidra and automotive UDS-related functions."
            + "Please determine if the current function exhibits UDS diagnostic protocol 27 sub-service characteristics, strictly splitting or combining into 4 or 3 bytes. Functions with segments like 'four = (char)Seed; one = (char)((uint)Seed >> 0x18); two = (char)((uint)Seed >> 0x10); three = (char)((uint)Seed >> 8);' are considered matches. Provide reasons."
        )
        json_structure_hint = "{    \"goal\":\"Find functions with UDS 27 service characteristics\",    \"function_logic\":\"{string}\",    \"result\":\"yes/no\",    \"reason\":\"xxxx\"}"
        user_meag = f"Provided code: {code_text}. Please analyze it. Please output in JSON structure ```json{json_structure_hint}```"
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
                print("[LLM_PARSE_ERROR] _llm_check_ud27 saved error context for recovery.")
            return data
        except Exception as e:
            save_llm_error_state({
                "phase": "_llm_check_ud27_exception",
                "error": str(e),
                "sys_content": sys_content,
                "user_meag": user_meag
            })
            print(f"[LLM_CALL_ERROR] _llm_check_ud27 {e}, error context saved for recovery.")
            return None

    # First, sequentially obtain decompiled text in the main thread to avoid accessing Ghidra context in sub-threads
    code_items = []
    for fn in ask_index:
        try:
            code_text = get_decompilation(fn)
            if code_text:
                code_items.append({"function": fn, "code": code_text})
        except Exception as e:
            # Ignore single function failure and continue
            pass

    # If a resume state exists and contains remaining functions, process only those
    try:
        if (resume_state or {}).get('remaining_functions'):
            remaining = set(resume_state.get('remaining_functions') or [])
            if remaining:
                code_items = [ci for ci in code_items if ci.get('function') in remaining]
                print(f"[RESUME] Processing only remaining functions: {list(remaining)}")
    except Exception:
        pass

    # Save the current list of functions to be checked for external review and recovery
    try:
        with open(os.path.join(LOG_DIR, "code_items_functions.json"), "w", encoding="utf-8") as f:
            json.dump([ci.get('function') for ci in code_items], f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # Record timing and stage 2 information
    stage2_elapsed = time.time() - stage2_start
    write_log(f"[TIMING] Stage 2 total time: {stage2_elapsed:.2f}s, function count={len(code_items)}")
    write_stage_log(2, {"ask_index": ask_index, "code_items_count": len(code_items), "stage_time": stage2_elapsed})

    def _evaluate_function_llm(item):
        # Call LLM only in sub-threads, do not access Ghidra or print
        resp = _llm_check_ud27(client_qwen, item["code"])
        if resp and resp.get("result") == "yes":
            return item
        return None

    log_separator("Stage 3: uds27_hits")
    stage3_start = time.time()
    write_log("[TIMING] Stage 3: LLM intelligent judgment started")
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
                # Record failure context, including remaining functions for next run
                try:
                    remaining_functions = [ci.get('function') for ci in code_items[idx:]]
                    save_llm_error_state({
                        "phase": "uds27_stage_error",
                        "failed_function": item.get('function'),
                        "remaining_functions": remaining_functions,
                        "code_items_functions": [ci.get('function') for ci in code_items]
                    })
                    print(f"[ERROR] UDS27 judgment failed, error recorded and can resume from {item.get('function')} next time.")
                except Exception:
                    pass
                break
            res = "unknown"
            if resp:
                # Support two types of return structures
                res = resp.get("result") or resp.get("is_goal_achieved", {}).get("result") or "unknown"
            print(f"[CHECK] {item['function']} -> {res}")
            print(code_text_for_check)  # Print full decompiled code
            print(resp.get("reason"))  # Print reason
            print("---")
            if res == "yes":
                total_lines = code_text_for_check.splitlines()
                if len(total_lines) < 5:
                    print(f"[SKIP] {item['function']} code lines too few: {len(total_lines)} < 5")
                    continue
                uds27_hits.append(item)

    if uds27_hits:
        print("Functions with UDS27 characteristics and their code snippets:")
        for item in uds27_hits:
            fn = item["function"]
            snippet = (item["code"] or "")[:600]
            print(f"[HIT] {fn}\n{snippet}\n---\n")
    else:
        print("No functions with UDS27 characteristics found.")
    stage3_elapsed = time.time() - stage3_start
    write_log(f"[TIMING] Stage 3 total time: {stage3_elapsed:.2f}s")
    try:
        write_stage_log(3, {"code_items": [ci.get('function') for ci in code_items], "uds27_hits": uds27_hits, "stage_time": stage3_elapsed})
    except Exception:
        write_stage_log(3, {"uds27_hits": uds27_hits, "stage_time": stage3_elapsed})

    # If this stage completes successfully and the error state is for UDS27, clear the error state file
    try:
        if (resume_state or {}).get('phase', '').startswith('uds27') and os.path.exists(ERR_STATE_FILE):
            os.remove(ERR_STATE_FILE)
            print("[RESUME_CLEAN] Cleared error state file for UDS27 stage.")
    except Exception:
        pass

    # Save hit results as JSON
    try:
        with open("uds27_hits.json", "w", encoding="utf-8") as f:
            json.dump(uds27_hits, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Failed to save results: {e}")

    # Subsequent process: Convert hit functions to a queue, proceed to main loop, and bind seed context
    seed_map_post = build_seed_map(function_name_list)
    seed_map = dict(seed_map_post)
    try:
        _ = seed_map_pre
    except NameError:
        seed_map_pre = {}
    for k, v in seed_map_pre.items():
        if v is not None:
            seed_map[k] = v
    
    # If ask_index comes from matching_functions, set all seeds to None
    if not function_name_list:
        seed_map = {fn: None for fn in ask_index}
        print(f"[SEED_RESET] ask_index comes from matching_functions, all seeds set to None")

    # Load Stage 4 results as input for Stage 5
    def load_uds27_overview():
        try:
            overview_path = os.path.join(LOG_DIR, "uds27_overview.json")
            if os.path.exists(overview_path):
                with open(overview_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"Failed to load uds27_overview.json: {e}")
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
        code_queue.append({"function": None, "code": "No related function found", "seed": None})
    print(code_queue)
    # Initialize main loop context with the first element
    current = code_queue.pop(0) if code_queue else {"function": None, "code": "No related function found", "seed": None}
    code = current.get("code")
    current_seed = current.get("seed")
    # Use unified LLM client configuration
    client_deepseek = get_llm_client("deepseek")
    function_list = []
    commend_list = []
    Index = 0
    loop_count = 0  # Limit loop iterations
    
    # Stage timing variables
    stage4_start = None
    stage5_start = None
    json_structure = [
        "{    \"goal\":\"Find functions with UDS 27 service characteristics\",    \"function_logic\":\"{string}\",    \"further_request\":{        \"type\":\"get_decompilation/get_cross_references\",        \"target_function_name\":\"{string}\"    },    \"is_goal_achieved\":{        \"result\":\"yes/no\",        \"matching_features\":[],        \"reason\":\"{string}\",          \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]    }}",
        "{    \"goal\":\"Reverse engineer seed transmission in UDS protocol 27 sub-service to identify Seed variable\",    \"function_logic_analysis\":\"{string}\",    \"identified_seed_variable\":\"{string}\",    \"seed_variable_transmission\":\"[\"string\",\"string\",...]\",   \"is_goal_achieved\":{        \"result\":\"yes\",        \"reason\":\"{string}\",        \"related_code\":\"{code}\",        \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]}}",
        "{    \"goal\":\"Reverse engineer seed transmission in UDS protocol 27 sub-service to identify Seed2Key code\",    \"function_logic\":\"{string}\",    \"seed_variable_transmission\":\"{string}\",    \"step_completeness_analysis\":\"{string}\",    \"further_request\":{        \"type\":\"{string}\",        \"target_fuc_or_val\":\"{string}\"    },    \"is_goal_achieved\":{        \"result\":\"yes/no\",        \"reason\":\"{string}\",        \"related_code\":\"{code}\",          \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]    }}",
        "{    \"goal\":\"Confirm whether all historical code for UDS protocol 27 sub-service functions is complete\",    \"functionality_assessment\":{ \"seed_generate\":\"yes/no\", \"seed_split\":\"yes/no\", \"seed2key\":\"yes/no\", \"key_compare\":\"yes/no\" },    \"related_functions\":{ \"seed_generate\":[\"{string}\"...], \"seed_split\":[\"{string}\"...], \"seed2key\":[\"{string}\"...], \"key_compare\":[\"{string}\"...] },    \"is_goal_achieved\":{ \"result\":\"yes/no\", \"reason\":\"{string}\" } }",
        "{    \"goal\":\"Scan for logical vulnerabilities in UDS27 code\",    \"vulnerability_analysis\":{ \"information_leakage\":{ \"hardcoded_keys\":[\"{string}\"...], \"sensitive_data\":[\"{string}\"...] }, \"algorithmic_flaws\":{ \"weak_seed2key\":[\"{string}\"...], \"short_keys\":[\"{string}\"...] }, \"auth_logic_flaws\":{ \"weak_randomness\":[\"{string}\"...], \"replay_vulnerable\":[\"{string}\"...] } },    \"further_request\":{        \"type\":\"get_decompilation/get_cross_references/get_global_var\",        \"target_fuc_or_val\":\"{string}\"    },    \"is_goal_achieved\":{        \"result\":\"yes/no\",        \"reason\":\"{string}\",        \"rename\":[        {            \"old_fun_name\":\"{string}\",            \"new_fun_name\":\"{string}\",        },...]    }}"
    ]
    LLMs_Object = [
        "Current goal: Find functions with UDS diagnostic protocol 27 sub-service characteristics. Note: UDS 27 characteristics include: a. Combining 4 bytes into one value; b. Splitting one value into 4 bytes. Additionally, the current inferred seed variable is: " + str(current_seed) + ". Please analyze as follows: 1. Analyze the entire function logic. 2. Specify a function for further analysis (optional operations: 1. Obtain the decompiled content of the target function (enter 'get_decompilation' in type). 2. Obtain cross-references to the target function (enter 'get_cross_references' in type)). 3. Determine if the goal is achieved (store matching feature types in JSON), and rename all analyzed function names to summarize their functionality.",
        "Current goal: Reverse engineer seed transmission in UDS protocol 27 sub-service to identify Seed variable. [Note]: The 27 sub-service handles security challenges, typically generating a random seed (Seed). The program sends the Seed via the CAN bus and: (i) In the first case, splits the Seed (e.g., 0x12345678) into 4 or 3 bytes (0x12, 0x34, 0x56, 0x78), then applies the Seed2Key algorithm to compute a key, which is compared with the key received from the challenger to determine success. (ii) In the second case, combines 3-4 bytes (e.g., 0x12, 0x34, 0x56, 0x78) into one value (e.g., 0x12345678), applies the Seed2Key algorithm to generate a key (e.g., 0xabcdefgh), splits the key into bytes, and compares it with the received key. Please analyze as follows: 1. Analyze the entire function logic. 2. Identify the random seed generation function from history and determine the seed variable. 3. Track the seed variable transmission logic [Note: Examine every line of code thoroughly, as there may be multiple transmission paths] (provide a variable transmission graph A->B->C). 4. Determine if the goal is achieved and rename all analyzed function names to summarize their functionality.",
        "Current goal: Reverse engineer seed transmission in UDS protocol 27 sub-service to identify main Seed2Key code. [Note]: The 27 sub-service handles security challenges, typically generating a random seed (Seed). The program sends the Seed via the CAN bus and: (i) In the first case, splits the Seed (e.g., 0x12345678) into 4 or 3 bytes (0x12, 0x34, 0x56, 0x78), then applies the Seed2Key algorithm to compute a key, which is compared with the key received from the challenger to determine success. (ii) In the second case, combines 3-4 bytes (e.g., 0x12, 0x34, 0x56, 0x78) into one value (e.g., 0x12345678), applies the Seed2Key algorithm to generate a key (e.g., 0xabcdefgh), splits the key into bytes, and compares it with the received key. Please analyze as follows: 1. Identify the random seed generation function from history and determine the seed variable. 2. Track the seed variable transmission logic (provide a variable transmission graph A->B->C). The UDS27 service logic is mostly complete; analyze the steps (Seed byte operations, Seed2Key conversion, Key byte operations, Key comparison). 3. To find the Seed2Key conversion function, specify a variable or function for further analysis (optional operations: 1. Obtain the decompiled content of the target function (enter 'get_decompilation' in type). 2. Obtain cross-references to the target function (enter 'get_cross_references' in type)). 4. Determine if the goal is achieved and rename all analyzed function names to summarize their functionality.",
        "Current goal: Confirm whether all historical code for UDS protocol 27 sub-service functions is complete, including 1. Seed generation, 2. Seed splitting, 3. Seed2Key algorithm, 4. Key comparison, and return all related function names. Please analyze as follows: 1. Review the historical process. 2. Check if the UDS 27 process is complete. 3. Return all function names covering the UDS 27 process.",
        "Current goal: Scan for logical vulnerabilities in UDS27 code. Focus on three types of vulnerabilities: 1. Information leakage (including hardcoded pre-shared keys and sensitive data); 2. Algorithmic flaws (including weak Seed2Key algorithms and short pre-shared keys); 3. Authentication logic flaws (including insufficient randomness and lack of replay attack protection). Analyze the current code, identify these vulnerabilities, and specify functions or variables for further analysis. For hardcoded keys, verify global variable contents."
    ]

    while True:
        print("----------------------------------------------------------------------------------------------------------")
        user_input = askString("User Input", "Please enter byte data:", "Please fill in:")
        old_commend = join_strings(commend_list)
        # Include current seed information in the prompt
        seed_hint = f"Current inferred seed variable: {current_seed}" if current_seed else ""
        
        # Special handling for Stage 5: Load uds27_overview.json as input
        if Index == 4:
            overview_data = load_uds27_overview()
            if overview_data:
                overview_hint = f"\nStage 4 results: {json.dumps(overview_data, ensure_ascii=False)}"
                code = code + overview_hint
        
        # Prevent index out of bounds
        if Index >= len(LLMs_Object) or Index >= len(json_structure):
            print(f"[ERROR] Index {Index} out of range, LLMs_Object length: {len(LLMs_Object)}, json_structure length: {len(json_structure)}")
            break
        response = LLMs_explain(get_llm_client(), code + "\n" + seed_hint, LLMs_Object[Index], json_structure[Index], user_input, old_commend)

        function_list = []
        
        print("----------------------------------------------------------------------------------------------------------")
        if response["is_goal_achieved"]["result"] == "no":
            # First goal: If determined as no, stop exploring current code and switch to the next
            if Index == 0:
                if code_queue:
                    next_item = code_queue.pop(0)
                    code = next_item.get("code")
                    current_seed = next_item.get("seed")
                    print(f"[NEXT] Switching to next code: {next_item.get('function')}")
                    continue
                else:
                    print("[DONE] First goal not achieved and no more code, proceeding to next goal stage")
                    Index = 1
                    continue
            # Third goal: Limit loop iterations, proceed to next goal after 5 iterations
            elif Index == 2:
                loop_count += 1
                if loop_count >= 5:
                    print(f"[LIMIT] Third goal loop limit reached ({loop_count}), forcing completion and proceeding to next goal")
                    Index = 3
                    loop_count = 0  # Reset counter
                    continue
            # Fifth goal: Limit loop iterations, proceed to next goal after 5 iterations
            elif Index == 4:
                loop_count += 1
                if loop_count >= 5:
                    print(f"[LIMIT] Fifth goal loop limit reached ({loop_count}), forcing completion and proceeding to next goal")
                    Index = 5
                    loop_count = 0  # Reset counter
                    continue
            if response["further_request"]["type"] == "get_cross_references":
                commend_list.append(str(response["further_request"]))
                function_name = response["further_request"].get("target_function_name")
                if function_name is None:
                    function_name = response["further_request"].get("target_fuc_or_val")
                if isinstance(function_name, list):
                    for item in function_name:
                        if 'DAT' not in item:
                            refs = print_cross_references(item, "FUN")
                        else:
                            refs = print_cross_references(item, "DAT")
                        if refs:
                            for ref in refs:
                                function_list.append(get_decompilation(ref))
                            code = join_strings(function_list)
                        else:
                            function_list.append(f"{function_name} has no function calls")
                            code = join_strings(function_list)
                elif isinstance(function_name, str):
                    if 'DAT' not in function_name:
                        refs = print_cross_references(function_name, "FUN")
                    else:
                        refs = print_cross_references(function_name, "DAT")
                    if refs:
                        for ref in refs:
                            function_list.append(get_decompilation(ref))
                        code = join_strings(function_list)
                    else:
                        function_list.append(f"{function_name} has no function calls")
                        code = join_strings(function_list)
                
            if response["further_request"]["type"] == "get_decompilation":
                commend_list.append(str(response["further_request"]))
                function_name = response["further_request"].get("target_function_name")
                if function_name is None:
                    function_name = response["further_request"].get("target_fuc_or_val")
                def _handle_decomp_target(name):
                    if not name or not isinstance(name, str):
                        return
                    if name.startswith("DAT_"):
                        function_list.append(f"[INVALID] Target {name} is not a function, cannot decompile. Please use get_global_var or get_cross_references.")
                        return
                    func_obj = getFunction(name)
                    if not func_obj:
                        function_list.append(f"[NOT_FOUND] Function not found: {name}")
                        return
                    res = get_decompilation(name)
                    if res:
                        function_list.append(res)
                    else:
                        function_list.append(f"[DECOMP_FAIL] Decompilation failed: {name}")

                if isinstance(function_name, list):
                    for item in function_name:
                        _handle_decomp_target(item)
                else:
                    _handle_decomp_target(function_name)
                code = join_strings(function_list)
            if response["further_request"]["type"] == "get_global_var":
                print('xxxxxxxxxxxx')
                symbol_name = response["further_request"].get("target_function_name")
                if symbol_name is None:
                    symbol_name = response["further_request"].get("target_fuc_or_val")
                data = []
                if isinstance(symbol_name, list):
                    for item in symbol_name:
                        data.append(f"{item} is {get_global_variable_data(item)}")
                else:
                    data.append(f"{symbol_name} is {get_global_variable_data(symbol_name)}")
                code = join_strings(data)

            # Handle Goal 4: Save and generate UDS27 functionality overview
            if response.get("goal") and "functionality is complete" in response.get("goal"):
                if stage4_start is None:
                    stage4_start = time.time()
                    write_log("[TIMING] Stage 4: Functionality completeness analysis started")
                try:
                    status_flag = response.get("is_goal_achieved", {}).get("result")
                    feature_map = response.get("functionality_assessment", {}) or {}
                    related_funcs = response.get("related_functions", {}) or {}
                    output = {
                        "goal": response.get("goal"),
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
                    log_separator("Stage 4: uds27_overview")
                    with open(os.path.join(LOG_DIR, "uds27_overview.json"), "w", encoding="utf-8") as f:
                        json.dump(output, f, ensure_ascii=False, indent=2)
                    
                    if stage4_start is not None:
                        stage4_elapsed = time.time() - stage4_start
                        write_log(f"[TIMING] Stage 4 total time: {stage4_elapsed:.2f}s")
                        output["stage_time"] = stage4_elapsed
                        stage4_start = None  # Reset to avoid duplicate calculation
                    
                    write_stage_log(4, output)
                    if status_flag == "yes":
                        print("UDS27 functionality is complete.")
                    else:
                        print(f"UDS27 functionality is incomplete, missing: {', '.join(missing)}")
                    concatenated = "\n\n".join(all_codes) if all_codes else ""
                    if concatenated:
                        print(concatenated)
                    code = concatenated if concatenated else code
                except Exception as e:
                    print(f"Failed to generate UDS27 overview: {e}")

        elif response["is_goal_achieved"]["result"] == "yes":
            Index = Index + 1
            loop_count = 0  # Reset counter
            # If there are more hit functions in the queue, switch to the next one to continue the main loop
            if code_queue:
                next_item = code_queue.pop(0)
                code = next_item.get("code")
                current_seed = next_item.get("seed")
            feature_lis = response["is_goal_achieved"].get("matching_features")
            if feature_lis is not None:
                if len(feature_lis) > 1:
                    Index = Index + 0
            # Handle Goal 4: Save and generate UDS27 functionality overview (complete case)
            if response.get("goal") and "functionality is complete" in response.get("goal"):
                try:
                    feature_map = response.get("functionality_assessment", {}) or {}
                    related_funcs = response.get("related_functions", {}) or {}
                    output = {
                        "goal": response.get("goal"),
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
                    log_separator("Stage 4: uds27_overview")
                    with open(os.path.join(LOG_DIR, "uds27_overview.json"), "w", encoding="utf-8") as f:
                        json.dump(output, f, ensure_ascii=False, indent=2)
                    
                    if stage4_start is not None:
                        stage4_elapsed = time.time() - stage4_start
                        write_log(f"[TIMING] Stage 4 total time: {stage4_elapsed:.2f}s")
                        output["stage_time"] = stage4_elapsed
                        stage4_start = None  # Reset to avoid duplicate calculation
                    
                    write_stage_log(4, output)
                    print("UDS27 functionality is complete.")
                    concatenated = "\n\n".join(all_codes) if all_codes else ""
                    if concatenated:
                        print(concatenated)
                    code = concatenated if concatenated else code
                except Exception as e:
                    print(f"Failed to generate UDS27 overview: {e}")

            # Handle Goal 5: Save and generate vulnerability scan results
            if response.get("goal") and "logical vulnerabilities" in response.get("goal"):
                if stage5_start is None:
                    stage5_start = time.time()
                    write_log("[TIMING] Stage 5: Vulnerability scan started")
                try:
                    vulnerability_analysis = response.get("vulnerability_analysis", {}) or {}
                    output = {
                        "goal": response.get("goal"),
                        "vulnerabilities": vulnerability_analysis,
                        "timestamp": datetime.now().isoformat()
                    }
                    log_separator("Stage 5: vulnerability_scan")
                    with open(os.path.join(LOG_DIR, "vulnerability_scan.json"), "w", encoding="utf-8") as f:
                        json.dump(output, f, ensure_ascii=False, indent=2)
                    
                    if stage5_start is not None:
                        stage5_elapsed = time.time() - stage5_start
                        write_log(f"[TIMING] Stage 5 total time: {stage5_elapsed:.2f}s")
                        output["stage_time"] = stage5_elapsed
                        stage5_start = None  # Reset to avoid duplicate calculation
                    
                    write_stage_log(5, output)
                    print("Vulnerability scan results saved to vulnerability_scan.json")
                except Exception as e:
                    print(f"Failed to generate vulnerability scan results: {e}")

            # Handle renaming
            rename_lis = response["is_goal_achieved"].get("rename")
            if rename_lis is not None:
                function_list = []
                for rename_item in rename_lis:
                    success, message = rename_function(rename_item["old_fun_name"], rename_item["new_fun_name"])
                    function_list.append(get_decompilation(rename_item["new_fun_name"]))
                code = join_strings(function_list)
            
            # Seed taint analysis 1: Analyze seed transmission from seed to UDS27
            if response.get("goal") == "Find functions related to random number generation":
                flag = 0
                rename_lis = response["is_goal_achieved"].get("rename")
                rename_item = rename_lis[0]
            
                refs = print_cross_references(rename_item["new_fun_name"], "FUN")
            
                if refs:
                    # Define a helper function to recursively check with depth limit
                    def check_refs(refs_list, matching_funcs, depth=0, previous_ref=None):
                        if depth >= 20:  # Stop recursion at max depth
                            return None
                        for ref in refs_list:
                            if ref in matching_funcs:
                                print(f"Hit {ref}")
                                return f"Among which {previous_ref if previous_ref else 'unknown'} is used to generate seed, {ref} is related to Seed2Key function" + get_decompilation(ref)
                            else:
                                call_refs = get_called_functions(ref)
                                print(call_refs)
                                for call_ref in call_refs:
                                    if call_ref in matching_funcs:
                                        print(f"Hit {call_ref}")
                                        return f"Among which {previous_ref if previous_ref else 'unknown'} is used to generate seed, {call_ref} is related to Seed2Key function" + get_decompilation(ref) + get_decompilation(call_ref)
                                sub_refs = print_cross_references(ref, "FUN")
                                if sub_refs:
                                    result = check_refs(sub_refs, matching_funcs, depth + 1, ref)  # Pass current ref as previous_ref for next recursion
                                    if result:
                                        return result
                        return None
            
                    result = check_refs(refs, matching_functions)
                    if result:
                        code = result
                        flag = 1
                    else:
                        code = "No related function found"
            
            # Seed taint analysis 2: Analyze seed transmission within UDS27
            elif response.get("goal") == "Reverse engineer seed transmission in UDS protocol 27 sub-service to identify Seed variable":
                seed_relationships = response.get("seed_variable_transmission")
                if seed_relationships is not None:
                    try:
                        leaf_nodes, not_leaf_nodes = find_leaf_nodes(seed_relationships)
                        print("Non-leaf nodes:", not_leaf_nodes)
                        relationships_2 = find_variable_relationships(code, not_leaf_nodes[0])
                        print("Relationships:", relationships_2)
                        leaf_nodes, not_leaf_nodes = find_leaf_nodes(relationships_2)
                        print("Optimized leaf nodes:", leaf_nodes)
                        filtered_and_grouped_nodes = filter_and_group_leaf_nodes(leaf_nodes)
                        print("Filtered and grouped leaf nodes:", filtered_and_grouped_nodes)
                        code = "Finding the Seed2Key key lies in " + join_strings(filtered_and_grouped_nodes) + " please perform cross-references on it" + code
                    except Exception as e:
                        print("Current function decompilation is irregular, causing taint analysis errors")
    
    # Script end time statistics
    script_total_time = time.time() - script_start_time
    write_log(f"[TIMING] Script total time: {script_total_time:.2f}s ({script_total_time/60:.2f} minutes)")
    write_log(f"[TIMING] Script end time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
