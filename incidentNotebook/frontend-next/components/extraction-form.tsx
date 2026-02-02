"use client"

import { useState, useEffect } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import * as z from "zod"
import { Loader2, Sparkles, Send } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
    Form,
    FormControl,
    FormDescription,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from "@/components/ui/form"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { extractIOCs, getModels } from "@/lib/api"
import { toast } from "sonner"
import { useRouter } from "next/navigation"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"

const formSchema = z.object({
    description: z.string().min(10, "Incident description must be at least 10 characters"),
    model: z.string().min(1, "Please select a model"),
})

interface ExtractionFormProps {
    caseId: string
    onExtractionComplete: () => void
}

export function ExtractionForm({ caseId, onExtractionComplete }: ExtractionFormProps) {
    const [isExtracting, setIsExtracting] = useState(false)
    const [availableModels, setAvailableModels] = useState<string[]>([])
    const router = useRouter()

    const form = useForm<z.infer<typeof formSchema>>({
        resolver: zodResolver(formSchema),
        defaultValues: {
            description: "",
            model: "mistral", // Default fallback
        },
    })

    useEffect(() => {
        const fetchModels = async () => {
            try {
                const models = await getModels();
                setAvailableModels(models);
                // If mistral is not in the list but others are, select the first one
                if (models.length > 0 && !models.includes("mistral")) {
                    form.setValue("model", models[0]);
                }
            } catch (error) {
                console.error("Failed to fetch models", error);
                toast.error("Failed to load available models");
            }
        }
        fetchModels();
    }, [form]);

    async function onSubmit(values: z.infer<typeof formSchema>) {
        setIsExtracting(true)
        try {
            const result = await extractIOCs(caseId, values.description, values.model)
            if (result.status === "success") {
                toast.success("Extraction completed", {
                    description: `Extracted ${result.counts.host_iocs} Host IOCs, ${result.counts.network_iocs} Network IOCs, and ${result.counts.timeline_events} Timeline events.`
                })
                form.reset()
                onExtractionComplete()
                router.refresh()
            } else {
                toast.error("Extraction failed", {
                    description: result.message
                })
            }
        } catch (error) {
            console.error(error)
            toast.error("An error occurred during extraction")
        } finally {
            setIsExtracting(false)
        }
    }

    return (
        <Card className="glass border-primary/20">
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Sparkles className="h-5 w-5 text-primary" />
                    AI Extraction
                </CardTitle>
                <CardDescription>
                    Paste your incident report or notes below to automatically extract IOCs and timeline events using LLMs.
                </CardDescription>
            </CardHeader>
            <CardContent>
                <Form {...form}>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                        <div className="grid gap-6 md:grid-cols-2">
                            <FormField
                                control={form.control}
                                name="model"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>LLM Model</FormLabel>
                                        <Select onValueChange={field.onChange} defaultValue={field.value} value={field.value}>
                                            <FormControl>
                                                <SelectTrigger>
                                                    <SelectValue placeholder="Select a model" />
                                                </SelectTrigger>
                                            </FormControl>
                                            <SelectContent>
                                                {availableModels.length > 0 ? (
                                                    availableModels.map((model) => (
                                                        <SelectItem key={model} value={model}>
                                                            {model}
                                                        </SelectItem>
                                                    ))
                                                ) : (
                                                    <SelectItem value="mistral" disabled>Loading models...</SelectItem>
                                                )}
                                            </SelectContent>
                                        </Select>
                                        <FormDescription>
                                            Select the Ollama model to use.
                                        </FormDescription>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />
                        </div>

                        <FormField
                            control={form.control}
                            name="description"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Incident Description</FormLabel>
                                    <FormControl>
                                        <Textarea
                                            placeholder="Paste the raw incident description, logs, or notes here..."
                                            className="min-h-[200px] resize-y font-mono text-sm"
                                            {...field}
                                        />
                                    </FormControl>
                                    <FormDescription>
                                        The AI will extract structure from unstructured text.
                                    </FormDescription>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        <Button type="submit" disabled={isExtracting} className="w-full">
                            {isExtracting ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Processing Extraction...
                                </>
                            ) : (
                                <>
                                    <Send className="mr-2 h-4 w-4" />
                                    Extract IOCs
                                </>
                            )}
                        </Button>
                    </form>
                </Form>
            </CardContent>
        </Card>
    )
}
