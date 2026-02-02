"use client"

import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area"
import { CaseDataResponse } from "@/lib/api"
import { Monitor, Globe, Clock, Copy } from "lucide-react"
import { Button } from "@/components/ui/button"
import { toast } from "sonner"

interface IOCTablesProps {
    data: CaseDataResponse
}

export function IOCTables({ data }: IOCTablesProps) {
    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text)
        toast.success("Copied to clipboard")
    }

    return (
        <Tabs defaultValue="host" className="w-full space-y-4">
            <TabsList className="grid w-full grid-cols-3 lg:w-[400px]">
                <TabsTrigger value="host" className="gap-2">
                    <Monitor className="h-4 w-4" /> Host
                </TabsTrigger>
                <TabsTrigger value="network" className="gap-2">
                    <Globe className="h-4 w-4" /> Network
                </TabsTrigger>
                <TabsTrigger value="timeline" className="gap-2">
                    <Clock className="h-4 w-4" /> Timeline
                </TabsTrigger>
            </TabsList>

            <TabsContent value="host">
                <Card className="glass">
                    <CardHeader>
                        <CardTitle>Host Indicators</CardTitle>
                        <CardDescription>File hashes, registry keys, and other host-based artifacts.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <ScrollArea className="h-[500px] w-full rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Type</TableHead>
                                        <TableHead>Indicator</TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Source</TableHead>
                                        <TableHead className="w-[50px]"></TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {data?.host_iocs.length === 0 && (
                                        <TableRow>
                                            <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                                                No Host IOCs found.
                                            </TableCell>
                                        </TableRow>
                                    )}
                                    {data?.host_iocs.map((ioc, idx) => (
                                        <TableRow key={idx}>
                                            <TableCell className="font-medium text-xs uppercase">{ioc.indicator_type}</TableCell>
                                            <TableCell className="font-mono text-xs">{ioc.indicator}</TableCell>
                                            <TableCell>
                                                <Badge variant="outline" className={ioc.status === 'Confirmed' ? 'border-red-500 text-red-500' : ''}>
                                                    {ioc.status}
                                                </Badge>
                                            </TableCell>
                                            <TableCell className="text-muted-foreground text-xs">{ioc.source}</TableCell>
                                            <TableCell>
                                                <Button variant="ghost" size="icon" onClick={() => copyToClipboard(ioc.indicator)}>
                                                    <Copy className="h-3 w-3" />
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                            <ScrollBar orientation="horizontal" />
                        </ScrollArea>
                    </CardContent>
                </Card>
            </TabsContent>

            <TabsContent value="network">
                <Card className="glass">
                    <CardHeader>
                        <CardTitle>Network Indicators</CardTitle>
                        <CardDescription>IP addresses, domains, and URLs.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <ScrollArea className="h-[500px] w-full rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Type</TableHead>
                                        <TableHead>Indicator</TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Source</TableHead>
                                        <TableHead className="w-[50px]"></TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {data?.network_iocs.length === 0 && (
                                        <TableRow>
                                            <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                                                No Network IOCs found.
                                            </TableCell>
                                        </TableRow>
                                    )}
                                    {data?.network_iocs.map((ioc, idx) => (
                                        <TableRow key={idx}>
                                            <TableCell className="font-medium text-xs uppercase">{ioc.indicator_type}</TableCell>
                                            <TableCell className="font-mono text-xs">{ioc.indicator}</TableCell>
                                            <TableCell>
                                                <Badge variant="outline" className={ioc.status === 'Confirmed' ? 'border-red-500 text-red-500' : ''}>
                                                    {ioc.status}
                                                </Badge>
                                            </TableCell>
                                            <TableCell className="text-muted-foreground text-xs">{ioc.source}</TableCell>
                                            <TableCell>
                                                <Button variant="ghost" size="icon" onClick={() => copyToClipboard(ioc.indicator)}>
                                                    <Copy className="h-3 w-3" />
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                            <ScrollBar orientation="horizontal" />
                        </ScrollArea>
                    </CardContent>
                </Card>
            </TabsContent>

            <TabsContent value="timeline">
                <Card className="glass">
                    <CardHeader>
                        <CardTitle>Timeline Events</CardTitle>
                        <CardDescription>Chronological sequence of events.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <ScrollArea className="h-[500px] w-full rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead className="w-[180px]">Timestamp (UTC)</TableHead>
                                        <TableHead>Activity</TableHead>
                                        <TableHead>System</TableHead>
                                        <TableHead>Source</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {data?.timeline_events.length === 0 && (
                                        <TableRow>
                                            <TableCell colSpan={4} className="text-center h-24 text-muted-foreground">
                                                No Timeline events found.
                                            </TableCell>
                                        </TableRow>
                                    )}
                                    {data?.timeline_events.map((event, idx) => (
                                        <TableRow key={idx}>
                                            <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                                                {new Date(event.timestamp_utc).toLocaleString()}
                                            </TableCell>
                                            <TableCell>{event.activity}</TableCell>
                                            <TableCell className="text-xs">{event.system_name}</TableCell>
                                            <TableCell className="text-xs text-muted-foreground">{event.evidence_source}</TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                            <ScrollBar orientation="horizontal" />
                        </ScrollArea>
                    </CardContent>
                </Card>
            </TabsContent>
        </Tabs>
    )
}
