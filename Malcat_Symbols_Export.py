import malcat
import json
import os

def run():
    if not analysis:
        return

    symbols_list = []
    output_path = r""

    print(f"[*] Exporting Virtual Addresses using analysis.map.a2v...")

    # analysis.syms is the documentation-preferred collection for symbols
    for sym in analysis.syms:
        name = str(sym.name).strip()
        
        # Skip empty or generic internal names
        if not name or name.startswith(('sub_', 'fn_', 'lbl_', 'ln_')):
            continue

        # Documentation fix: 
        # sym.address is an 'Effective Address'. 
        # a2v() converts it to the absolute Virtual Address (VA).
        va = analysis.map.a2v(sym.address)

        if va is not None:
            symbols_list.append({
                "name": name,
                "address": hex(va)
            })

    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(symbols_list, f, indent=4)
        
        print(f"[+] Successfully exported {len(symbols_list)} symbols.")
        # Verification for your specific address
        for s in symbols_list:
            if "Cmd).Run" in s['name']:
                print(f"[!] Target Check: {s['name']} -> {s['address']}")
                
    except Exception as e:
        print(f"[-] Error: {str(e)}")

if __name__ == '__main__':
    run()
