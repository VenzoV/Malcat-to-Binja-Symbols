import malcat
import json
import os

def run():
    if not analysis:
        return

    symbols_list = []
    output_path = r""
    BASE_ADDRESS = 0x400000

    print(f"[*] Exporting Virtual Addresses from {analysis.file.name}...")

    for sym in analysis.symbols:
        # 1. Skip empty or null names
        if not sym.name or not str(sym.name).strip():
            continue

        offset = getattr(sym, 'address', None)
        if offset is not None:
            va = getattr(sym, 'va', None)
            
            # Ensure va is a plain integer; fallback to manual calc
            if va is None or not isinstance(va, int):
                va = BASE_ADDRESS + offset

            symbols_list.append({
                "name": str(sym.name),
                "address": hex(va) # Write as hex string (e.g. "0x515c30")
            })

    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(symbols_list, f, indent=4)
        
        print(f"[+] Successfully exported {len(symbols_list)} symbols.")
        print(f"[+] Output saved to: {output_path}")
                
    except Exception as e:
        print(f"[-] JSON Error: {str(e)}")

if __name__ == '__main__':
    run()
