# Wireless Security Testing Toolkit (WSTT)

## **Overview**
WSTT provides a single commmand for managing wireless network interfaces, enabling monitor mode, resetting interfaces, and checking interface status.

The tools simplifies the process of switching between **managed** and **monitor** modes, commonly required for security testing and packet analysis.

---

## **Features**
- Enable **Monitor Mode** for packet capture and security testing  
- Enable **Managed Mode** for normal Wi-Fi usage  
- **Reset Wireless Interface** (down/up cycle without changing mode)  
- **Check Current Interface Status**  

---

## **Installation**
### **Prerequisites**
Before using WSTT, ensure you have the required dependencies installed:
```bash
sudo apt update
sudo apt install iw iproute2
```

### Clone the repository
```bash
git clone https://github.com/your-repo/wstt.git
cd wstt
```

### Make the script executable
```bash
chmod +x wstt_interface.py
```

---

## **Usage**
The script accepts one interface at a time and provides various options.

### General Syntax
```bash
./wstt_interface.py -i <interface> [options]
```

### Enable Monitor Mode
```bash
./wstt_interface.py -i wlan0 -m monitor
```

**Expected Output**
```bash
[INFO] Interface wlan0 is now down.
[INFO] Changing wlan0 to Monitor mode...
[INFO] Interface wlan0 is now up.
[SUCCESS] wlan0 is set to Monitor mode.
```

### Enable Managed Mode
```bash
./wstt_interface.py -i wlan0 -m managed
```

**Expected Output**
```bash
[INFO] Interface wlan0 is now down.
[INFO] Changing wlan0 to Managed mode...
[INFO] Interface wlan0 is now up.
[SUCCESS] wlan0 is set to Managed mode.
```

### Reset Interface (Down/Up Cycle)
```bash
./wstt_interface.py -i wlan0 -r
```

**Expected Output**
```bash
[INFO] Interface wlan0 is now down.
[INFO] Interface wlan0 is now up.
[INFO] Interface wlan0 has been reset.
```

### Check Interface Status
```bash
./wstt_interface.py -i wlan0 -s
```

**Expected Output**
```bash
[INFO] wlan0 is currently set to Managed mode.
```

---

## **Exit Codes**
| Code | Meaning                                   |
| ---- | ----------------------------------------- |
| `0`  | Success                                   |
| `1`  | Error: Invalid Input or Execution Failure |
| `2`  | Interface Not Found                       |

---

## **Troubleshooting**
- Error: ```Command not found: iw```
- Solution: Install ```iw``` with:
```bash
sudo apt install iw
```

- Error: ```Interface not found```
- Solution: Verify the correct interface name with:
```bash
ip link show
```

---

## **Logging**
All actions and errors are logged to ```wstt.log```:
```bash
tail -f wstt.log
```

---

## **Licence**
This project is licenced under the MIT Licence.

---

## **Author**
- Paul Smurthwaite
- 12 March 2025
- TM470-25B
