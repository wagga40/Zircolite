#!/bin/bash

# ===================================================
# Universal Binary Creator for macOS
# Creates a universal binary from x86_64 and arm64 binaries
# ===================================================

# Function for formatted message display
print_msg() {
    local type=$1
    local message=$2
    
    case "$type" in
        "ERROR")   echo -e "\033[1;31mERROR:\033[0m $message" ;;
        "INFO")    echo -e "\033[1;32mINFO:\033[0m $message" ;;
        "WARNING") echo -e "\033[1;33mWARNING:\033[0m $message" ;;
        "USAGE")   echo -e "\033[1;34mUSAGE:\033[0m $message" ;;
        "OPTIONS") echo -e "\033[1;34mOPTIONS:\033[0m $message" ;;
        "NOTE")    echo -e "\033[1;34mNOTE:\033[0m $message" ;;
        "PROCESS") echo -e "\033[1;34mPROCESS:\033[0m $message" ;;
        "SUCCESS") echo -e "\033[1;32mSUCCESS:\033[0m $message" ;;
        "DRY_RUN") echo -e "\033[1;33m[DRY RUN]\033[0m $message" ;;
        *)         echo "$message" ;;
    esac
}

# Display title
echo "====================================================="
echo "          Universal Binary Creator for macOS         "
echo "====================================================="

# Check for required tools
if ! command -v lipo &> /dev/null; then
    print_msg "ERROR" "'lipo' command not found. Please install Xcode command line tools."
    exit 1
fi

# Initialize dry-run flag
DRY_RUN=false

# Parse options
while getopts "d" opt; do
    case $opt in
        d) DRY_RUN=true ;;
        *) ;;
    esac
done
shift $((OPTIND-1))

# Validate command line arguments
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    print_msg "USAGE" "$0 [-d] <binary1> <binary2> [<output_universal_binary>]"
    print_msg "OPTIONS" ""
    echo "  -d    Dry run mode (show commands without executing them)"
    print_msg "NOTE" "The script will automatically detect the architecture of each binary."
    echo "      If no output binary name is provided, a random name will be generated."
    exit 1
fi

# Store input and output paths
BINARY1="$1"
BINARY2="$2"
OUTPUT_BINARY="$3"

# Generate random output name if not provided
if [ -z "$OUTPUT_BINARY" ]; then
    RANDOM_SUFFIX=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
    OUTPUT_BINARY="universal_binary_${RANDOM_SUFFIX}"
    print_msg "WARNING" "No output name provided. Using random name: $OUTPUT_BINARY"
fi

# Validate input files exist
for BINARY in "$BINARY1" "$BINARY2"; do
    if [ ! -f "$BINARY" ]; then
        print_msg "ERROR" "Binary '$BINARY' not found!"
        exit 1
    fi
done

# Detect architectures of input binaries
ARCH1=$(lipo -archs "$BINARY1")
ARCH2=$(lipo -archs "$BINARY2")

# Check if we have both required architectures
if [[ ! "$ARCH1 $ARCH2" =~ "x86_64" ]] || [[ ! "$ARCH1 $ARCH2" =~ "arm64" ]]; then
    print_msg "ERROR" "Missing required architecture!"
    echo "Binary 1 ($BINARY1): $ARCH1"
    echo "Binary 2 ($BINARY2): $ARCH2"
    echo "Both x86_64 and arm64 architectures are required."
    exit 1
fi

# Identify which binary is which architecture
X86_BINARY=""
ARM_BINARY=""

if [[ "$ARCH1" =~ "x86_64" ]]; then X86_BINARY="$BINARY1"; fi
if [[ "$ARCH1" =~ "arm64" ]]; then ARM_BINARY="$BINARY1"; fi
if [[ "$ARCH2" =~ "x86_64" ]]; then X86_BINARY="$BINARY2"; fi
if [[ "$ARCH2" =~ "arm64" ]]; then ARM_BINARY="$BINARY2"; fi

print_msg "INFO" "Detected x86_64 binary: $X86_BINARY"
print_msg "INFO" "Detected arm64 binary: $ARM_BINARY"

# Ensure output directory exists
OUTPUT_DIR=$(dirname "$OUTPUT_BINARY")
if [ ! -d "$OUTPUT_DIR" ] && [ "$OUTPUT_DIR" != "." ]; then
    if [ "$DRY_RUN" = true ]; then
        print_msg "DRY_RUN" "Would create directory: $OUTPUT_DIR"
    else
        mkdir -p "$OUTPUT_DIR"
    fi
fi

# Create the universal binary
print_msg "PROCESS" "Creating universal binary..."
if [ "$DRY_RUN" = true ]; then
    print_msg "DRY_RUN" "Would execute: lipo -create -output \"$OUTPUT_BINARY\" \"$X86_BINARY\" \"$ARM_BINARY\""
    print_msg "DRY_RUN" "Would execute: chmod +x \"$OUTPUT_BINARY\""
    print_msg "DRY_RUN" "Universal binary would be created: $OUTPUT_BINARY"
else
    if lipo -create -output "$OUTPUT_BINARY" "$X86_BINARY" "$ARM_BINARY"; then
        chmod +x "$OUTPUT_BINARY"
        print_msg "SUCCESS" "Universal binary created successfully: $OUTPUT_BINARY"
        lipo -info "$OUTPUT_BINARY"
    else
        print_msg "ERROR" "Failed to create universal binary."
        exit 1
    fi
fi