"use client"

import { useEffect, useState, use } from "react"
import { useParams, useRouter } from "next/navigation"
import { ArrowLeft, Trash2, Database, Sparkle } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { getCase, getCaseData, deleteCase, Case, CaseDataResponse } from "@/lib/api"
import { ExtractionForm } from "@/components/extraction-form"
import { IOCTables } from "@/components/ioc-tables"
import { Skeleton } from "@/components/ui/skeleton"
import { toast } from "sonner"
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger,
} from "@/components/ui/alert-dialog"

export default function CaseDetailPage() {
    const params = useParams()
    const router = useRouter()
    // Handle potentially undefined id
    const id = typeof params.id === 'string' ? params.id : Array.isArray(params.id) ? params.id[0] : null

    const [caseItem, setCaseItem] = useState<Case | null>(null)
    const [caseData, setCaseData] = useState<CaseDataResponse | null>(null)
    const [loading, setLoading] = useState(true)
    const [activeTab, setActiveTab] = useState("data")

    const fetchData = async () => {
        if (!id) return
        setLoading(true)
        try {
            const [caseRes, dataRes] = await Promise.all([
                getCase(id),
                getCaseData(id)
            ])
            setCaseItem(caseRes)
            setCaseData(dataRes)
        } catch (error) {
            console.error("Failed to fetch case data", error)
            toast.error("Failed to load case data")
        } finally {
            setLoading(false)
        }
    }

    const handleDelete = async () => {
        if (!id) return
        try {
            await deleteCase(id)
            toast.success("Case deleted successfully")
            router.push("/")
        } catch (error) {
            console.error(error)
            toast.error("Failed to delete case")
        }
    }

    useEffect(() => {
        if (id) {
            fetchData()
        }
    }, [id])

    if (!id) return <div>Invalid Case ID</div>

    if (loading && !caseItem) {
        return (
            <div className="space-y-4">
                <Skeleton className="h-12 w-1/3" />
                <Skeleton className="h-[500px] w-full" />
            </div>
        )
    }

    if (!caseItem) {
        return <div className="text-center py-20">Case not found</div>
    }

    return (
        <div className="flex flex-col gap-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <Button variant="outline" size="icon" onClick={() => router.push("/")}>
                        <ArrowLeft className="h-4 w-4" />
                    </Button>
                    <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                            <h1 className="text-2xl font-bold tracking-tight">{caseItem.name}</h1>
                            <Badge variant="outline" className="text-muted-foreground">
                                {caseItem.status}
                            </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground font-mono">ID: {caseItem.case_id}</p>
                    </div>
                </div>

                <AlertDialog>
                    <AlertDialogTrigger asChild>
                        <Button variant="destructive" size="sm" className="gap-2">
                            <Trash2 className="h-4 w-4" /> Delete Case
                        </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                        <AlertDialogHeader>
                            <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
                            <AlertDialogDescription>
                                This action cannot be undone. This will permanently delete the case
                                and all gathered data artifacts (IOCs, timeline events).
                            </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={handleDelete} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                                Delete
                            </AlertDialogAction>
                        </AlertDialogFooter>
                    </AlertDialogContent>
                </AlertDialog>
            </div>

            {/* Main Content */}
            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
                <TabsList>
                    <TabsTrigger value="data" className="gap-2">
                        <Database className="h-4 w-4" /> Data View
                    </TabsTrigger>
                    <TabsTrigger value="extraction" className="gap-2">
                        <Sparkle className="h-4 w-4" /> Extraction
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="data" className="space-y-4">
                    {caseData ? (
                        <IOCTables data={caseData} />
                    ) : (
                        <div className="text-center py-20 text-muted-foreground">No data available</div>
                    )}
                </TabsContent>

                <TabsContent value="extraction" className="space-y-4">
                    <ExtractionForm caseId={id} onExtractionComplete={() => {
                        fetchData() // Refresh data
                        setActiveTab("data") // Switch to data view
                    }} />
                </TabsContent>
            </Tabs>
        </div>
    )
}
