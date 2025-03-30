#!/bin/bash

set -e

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

# Function to determine latest release
get_latest_release() {
    curl --silent "https://api.github.com/repos/omerbenamram/evtx/releases/latest" | 
    grep '"tag_name":' | 
    sed -E 's/.*"([^"]+)".*/\1/'
}

# Final binary names
MACOS_FINAL_BINARY_NAME="evtx_dump_mac"
LINUX_FINAL_BINARY_NAME="evtx_dump_lin"
LINUX_ARM_FINAL_BINARY_NAME="evtx_dump_lin_arm"
WINDOWS_FINAL_BINARY_NAME="evtx_dump_win.exe"

# Check if linux cli tools are installed
if ! command -v curl &> /dev/null; then
    print_msg "ERROR" "curl could not be found"
    exit 1
fi
# Initialize force flag
FORCE_REMOVE=false

# Parse options '-f' to force remove existing files
while getopts "f" opt; do
    case $opt in
        f) FORCE_REMOVE=true ;;
        *) ;;
    esac
done
shift $((OPTIND-1))

# Check if destination files already exist
if [ -f "$LINUX_FINAL_BINARY_NAME" ] || [ -f "$LINUX_ARM_FINAL_BINARY_NAME" ] || [ -f "$WINDOWS_FINAL_BINARY_NAME" ] || [ -f "$MACOS_FINAL_BINARY_NAME" ]; then
    if [ "$FORCE_REMOVE" = true ]; then
        print_msg "PROCESS" "Force removing existing files..."
        rm -f "$LINUX_FINAL_BINARY_NAME" "$LINUX_ARM_FINAL_BINARY_NAME" "$WINDOWS_FINAL_BINARY_NAME" "$MACOS_FINAL_BINARY_NAME"
    else
        print_msg "WARNING" "Destination files already exist. Do you want to remove them? (y/n)"
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            print_msg "PROCESS" "Removing existing files..."
            rm -f "$LINUX_FINAL_BINARY_NAME" "$LINUX_ARM_FINAL_BINARY_NAME" "$WINDOWS_FINAL_BINARY_NAME" "$MACOS_FINAL_BINARY_NAME"
        else
            print_msg "ERROR" "Operation cancelled by user"
            exit 1
        fi
    fi
fi

# Check if destination directories already exist, if so remove them
if [ -d "$INSTALL_DIR" ]; then
    print_msg "PROCESS" "Removing existing destination directory: $INSTALL_DIR"
    rm -rf $INSTALL_DIR || print_msg "ERROR" "Failed to remove install directory: $INSTALL_DIR"
    exit 1
fi

# Get the latest release version
LATEST_VERSION=$(get_latest_release)
print_msg "INFO" "Latest release: $LATEST_VERSION"

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
print_msg "INFO" "Created temporary directory: $TEMP_DIR"

# Download all assets from the latest release
print_msg "PROCESS" "Downloading binaries from $LATEST_VERSION..."
ASSETS_URL="https://api.github.com/repos/omerbenamram/evtx/releases/latest"
DOWNLOAD_URLS=$(curl -s $ASSETS_URL | grep "browser_download_url" | cut -d '"' -f 4)

# Download each binary
for url in $DOWNLOAD_URLS; do
    filename=$(basename $url)
    # Skip musl binaries
    if [[ "$filename" == *"musl"* ]]; then
        print_msg "INFO" "Skipping musl binary: $filename"
        continue
    fi
    print_msg "PROCESS" "Downloading $filename..."
    curl -s -L -o "$TEMP_DIR/$filename" "$url"
done

# Create a directory for the binaries if it doesn't exist
INSTALL_DIR="./evtx_binaries"
mkdir -p $INSTALL_DIR

# Move the binaries to the install directory
print_msg "PROCESS" "Moving binaries to $INSTALL_DIR..."
mv $TEMP_DIR/* $INSTALL_DIR/

# Clean up
rmdir $TEMP_DIR
print_msg "INFO" "Temporary directory removed"

# Make binaries executable
chmod +x $INSTALL_DIR/*
print_msg "SUCCESS" "All binaries downloaded and made executable in $INSTALL_DIR"

# Detect and handle macOS binaries
print_msg "PROCESS" "Detecting macOS binaries for universal binary creation..."

# Find macOS binaries and rename all binaries in one pass
MACOS_X86_BINARY=""
MACOS_ARM_BINARY=""
UNIVERSAL_BINARY="$INSTALL_DIR/$MACOS_FINAL_BINARY_NAME"


print_msg "PROCESS" "Renaming binaries with platform-specific names..."

for binary in $INSTALL_DIR/*; do
    # Skip if not a file
    [ -f "$binary" ] || continue
    
    # Use file command to detect binary type
    FILE_INFO=$(file "$binary")
    
    # Process based on binary type
    if [[ "$FILE_INFO" == *"ELF"*"x86-64"* ]]; then
        # Linux x86_64
        mv "$binary" "$INSTALL_DIR/$LINUX_FINAL_BINARY_NAME"
        print_msg "INFO" "Renamed $(basename "$binary") to $LINUX_FINAL_BINARY_NAME"
    elif [[ "$FILE_INFO" == *"ELF"*"aarch64"* ]]; then
        # Linux ARM64
        mv "$binary" "$INSTALL_DIR/$LINUX_ARM_FINAL_BINARY_NAME"
        print_msg "INFO" "Renamed $(basename "$binary") to $LINUX_ARM_FINAL_BINARY_NAME"
    elif [[ "$FILE_INFO" == *"PE"*"executable"* ]] || [[ "$binary" == *".exe" ]]; then
        # Windows
        mv "$binary" "$INSTALL_DIR/$WINDOWS_FINAL_BINARY_NAME"
        print_msg "INFO" "Renamed $(basename "$binary") to $WINDOWS_FINAL_BINARY_NAME"
    elif [[ "$FILE_INFO" == *"Mach-O"* ]]; then
        if [[ "$FILE_INFO" == *"x86_64"* ]]; then
            print_msg "INFO" "Found macOS x86_64 binary: $(basename "$binary")"
            MACOS_X86_BINARY="$binary"
        elif [[ "$FILE_INFO" == *"arm64"* ]]; then
            print_msg "INFO" "Found macOS arm64 binary: $(basename "$binary")"
            MACOS_ARM_BINARY="$binary"
        fi
    fi
done

# Create universal binary if both architectures are found
if [ -n "$MACOS_X86_BINARY" ] && [ -n "$MACOS_ARM_BINARY" ]; then
    print_msg "PROCESS" "Creating universal binary from x86_64 and arm64 binaries..."
    ./create_universal_bin_macos.sh "$MACOS_X86_BINARY" "$MACOS_ARM_BINARY" "$UNIVERSAL_BINARY"
    # Remove the architecture-specific binaries
    rm -f "$MACOS_X86_BINARY" "$MACOS_ARM_BINARY"
    print_msg "INFO" "Created universal macOS binary: evtx_dump_mac"
elif [ -n "$MACOS_X86_BINARY" ]; then
    # If only x86_64 is available
    mv "$MACOS_X86_BINARY" "$UNIVERSAL_BINARY"
    print_msg "INFO" "Only x86_64 macOS binary available, renamed to evtx_dump_mac"
elif [ -n "$MACOS_ARM_BINARY" ]; then
    # If only arm64 is available
    mv "$MACOS_ARM_BINARY" "$UNIVERSAL_BINARY"
    print_msg "INFO" "Only arm64 macOS binary available, renamed to evtx_dump_mac"
fi

# Put all the binaries in the root directory
mv $INSTALL_DIR/* .

# Remove the install directory
rm -rf $INSTALL_DIR || print_msg "ERROR" "Failed to remove install directory: $INSTALL_DIR"

print_msg "SUCCESS" "All binaries downloaded and made executable in $INSTALL_DIR"
