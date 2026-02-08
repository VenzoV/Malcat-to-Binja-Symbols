import json
from binaryninja import Symbol, SymbolType, log_info

input_path = r""

def import_malcat_symbols(bv):
    try:
        with open(input_path, "r") as f:
            symbols = json.load(f)
    except Exception as e:
        print(f"Error reading JSON: {e}")
        return

    # Start a single transaction for speed and 'Undo' support
    bv.begin_undo_actions()
    
    count = 0
    for sym_data in symbols:
        # The address is a hex string (e.g., "0x515c30")
        addr = int(sym_data['address'], 16)
        name = sym_data['name']
        
        # Check if address is within the binary range
        if bv.get_segment_at(addr):
            # 1. Define the symbol
            new_sym = Symbol(SymbolType.FunctionSymbol, addr, name)
            bv.define_user_symbol(new_sym)
            
            # 2. Force function creation
            # Note: add_function is safe to call even if it already exists
            bv.add_function(addr)
            count += 1
        else:
            print(f"Skipping {name}: Address {hex(addr)} is out of bounds.")

    # Commit changes
    bv.commit_undo_actions()
    
    # Refresh the UI and analysis
    bv.update_analysis_and_wait()
    print(f"Import complete! Successfully applied {count} symbols.")

# Run the function
import_malcat_symbols(bv)
