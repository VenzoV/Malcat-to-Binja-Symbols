import malcat
import json

output_path = r""

# The hardcoded difference between File Offset and Virtual Address
# Derived from SendReply: 0x515c30 (VA) - 0x115030 (Offset)
delta = 0x400C00

symbols = []
for sym in analysis.syms:
    # Filter: Must be a function AND must have a non-empty name
    if sym.type == malcat.Symbol.Type.FUNCTION and sym.name.strip():
        # Apply the hardcoded manual math
        va = sym.address + delta
        
        symbols.append({
            "address": hex(va), 
            "name": sym.name
        })

try:
    with open(output_path, "w") as f:
        json.dump(symbols, f, indent=4)
    print(f"Success! Exported {len(symbols)} functions using hardcoded delta {hex(delta)}.")
    if symbols:
        # This will now show 0x515c30 for SendReply
        print(f"Verified: {symbols[0]['name']} is now at {symbols[0]['address']}")
except Exception as e:
    print(f"Failed to save: {e}")
