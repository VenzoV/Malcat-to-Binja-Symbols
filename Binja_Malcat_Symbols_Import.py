import json
from binaryninja import Symbol, SymbolType

input_path = r""

with open(input_path, "r") as f:
    symbols = json.load(f)

for sym_data in symbols:
    addr = int(sym_data['address'], 16) # Convert "0x..." string to int
    name = sym_data['name']
    
    if bv.is_valid_offset(addr):
        # Define the symbol
        new_sym = Symbol(SymbolType.FunctionSymbol, addr, name)
        bv.define_user_symbol(new_sym)
        
        # Force a function to be created if Binja missed it
        if not bv.get_function_at(addr):
            bv.add_function(addr)

bv.update_analysis_and_wait()
print("Import complete!")
