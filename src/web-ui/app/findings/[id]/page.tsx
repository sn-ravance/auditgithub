"use client"

import { useEffect, useState } from "react"
import { useParams, useRouter } from "next/navigation"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { AiRemediationCard } from "@/components/ai-remediation-card"
import { ExceptionDialog } from "@/components/ExceptionDialog"
import { AskAIDialog } from "@/components/AskAIDialog"
import { Loader2, ArrowLeft, Sparkles } from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"

const API_BASE = "http://localhost:8000"

export default function FindingDetailsPage() {
    const params = useParams()
    const router = useRouter()
    const id = params.id as string
    const [finding, setFinding] = useState<any>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        const fetchFinding = async () => {
            try {
                const res = await fetch(`${API_BASE}/findings/${id}`)
                if (!res.ok) throw new Error("Finding not found")
                const data = await res.json()
                setFinding(data)
            } catch (err) {
                setError("Failed to load finding details")
            } finally {
                setLoading(false)
            }
        }

        if (id) fetchFinding()
    }, [id])

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    if (error || !finding) {
        return (
            <div className="flex h-screen flex-col items-center justify-center gap-4">
                <p className="text-red-500">{error || "Finding not found"}</p>
                <Button variant="outline" onClick={() => router.back()}>Go Back</Button>
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => router.back()}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-2xl font-bold tracking-tight">{finding.title}</h1>
                    <div className="flex items-center gap-2 text-muted-foreground">
                        {finding.repository_id ? (
                            <Link href={`/projects/${finding.repository_id}`} className="text-blue-600 hover:underline">
                                {finding.repo_name}
                            </Link>
                        ) : (
                            <span>{finding.repo_name}</span>
                        )}
                        <span>•</span>
                        <span>{finding.id.substring(0, 8)}</span>
                    </div>
                </div>
                <div className="ml-auto flex items-center gap-2">
                    <ExceptionDialog finding={finding} onDeleted={() => router.push("/findings")} />
                    <Badge
                        className={
                            finding.severity === "Critical" ? "bg-red-500" :
                            finding.severity === "High" ? "bg-orange-500" : "bg-blue-500"
                        }
                    >
                        {finding.severity}
                    </Badge>
                </div>
            </div>

            <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-6">
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0">
                            <CardTitle>Details</CardTitle>
                            <AskAIDialog findingId={finding.id} onDescriptionUpdated={() => {
                                // Refresh finding data after description update
                                fetch(`${API_BASE}/findings/${id}`)
                                    .then(res => res.json())
                                    .then(data => setFinding(data))
                            }} />
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div>
                                <h3 className="font-semibold mb-2">Description</h3>
                                {finding.description?.startsWith('**AI Security Analysis') ? (
                                    <div className="rounded-lg border bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-950/20 dark:to-blue-950/20 p-4">
                                        <div className="flex items-center gap-2 mb-3 text-purple-600 dark:text-purple-400">
                                            <Sparkles className="h-4 w-4" />
                                            <span className="text-xs font-medium uppercase tracking-wide">AI-Enhanced Description</span>
                                        </div>
                                        <div className="prose prose-sm dark:prose-invert max-w-none prose-headings:text-base prose-headings:font-semibold prose-p:text-muted-foreground prose-ul:text-muted-foreground prose-li:text-muted-foreground">
                                            <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.description}</ReactMarkdown>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-sm text-muted-foreground bg-muted p-3 rounded-md">
                                        {finding.description || 'No description available.'}
                                    </p>
                                )}
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <h3 className="font-semibold">Scanner</h3>
                                    <p className="text-sm">{finding.scanner_name}</p>
                                </div>
                                <div>
                                    <h3 className="font-semibold">Status</h3>
                                    <p className="text-sm capitalize">{finding.status}</p>
                                </div>
                            </div>
                            {finding.file_path && (
                                <div>
                                    <h3 className="font-semibold">Location</h3>
                                    <p className="text-sm font-mono bg-muted p-2 rounded">
                                        {finding.file_path}:{finding.line_start}
                                    </p>
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {finding.code_snippet && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Code Context</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <pre className="overflow-x-auto rounded-md bg-slate-950 p-4 text-xs text-slate-50">
                                    <code>{finding.code_snippet}</code>
                                </pre>
                            </CardContent>
                        </Card>
                    )}
                </div>

                <div className="space-y-6">
                    <AiRemediationCard
                        findingId={finding.id}
                        vulnType={finding.title}
                        description={finding.description || ""}
                        context={finding.code_snippet || ""}
                        language="python" // TODO: Detect language dynamically
                        existingRemediations={finding.remediations}
                    />
                </div>
            </div>
        </div>
    )
}
