"use client"

import { useEffect, useRef, useCallback } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import Link from "next/link"
import { Eye } from "lucide-react"

interface ThreatData {
    critical: number
    high: number
    medium: number
    secrets: number
    abandoned: number
    staleContributors: number
    overallScore: number // 0-100
}

interface ThreatRadarProps {
    data: ThreatData
    onSegmentClick?: (segment: string) => void
}

// Calculate letter grade from score
function getGrade(score: number): { letter: string; color: string } {
    if (score >= 90) return { letter: "A", color: "#22c55e" }
    if (score >= 80) return { letter: "B", color: "#84cc16" }
    if (score >= 70) return { letter: "C", color: "#eab308" }
    if (score >= 60) return { letter: "D", color: "#f97316" }
    return { letter: "F", color: "#ef4444" }
}

// Threat configuration
const THREATS = [
    { key: "critical", label: "CRIT", fullLabel: "Critical", color: "#ef4444", link: "/findings?severity=critical" },
    { key: "high", label: "HIGH", fullLabel: "High", color: "#f97316", link: "/findings?severity=high" },
    { key: "secrets", label: "SECR", fullLabel: "Secrets", color: "#a855f7", link: "/attack-surface" },
    { key: "staleContributors", label: "STAL", fullLabel: "Stale Users", color: "#3b82f6", link: "/attack-surface" },
    { key: "abandoned", label: "ABAN", fullLabel: "Abandoned", color: "#6b7280", link: "/attack-surface" },
    { key: "medium", label: "MED", fullLabel: "Medium", color: "#eab308", link: "/findings?severity=medium" },
]

// Blip state for animation - exactly 6 blips, one per threat type
interface Blip {
    threatKey: string
    angle: number
    distance: number
    targetDistance: number // Where the blip is moving to
    label: string
    color: string
    value: number
}

export function ThreatRadar({ data, onSegmentClick }: ThreatRadarProps) {
    const canvasRef = useRef<HTMLCanvasElement>(null)
    const animationRef = useRef<number>()
    const sweepAngleRef = useRef(0)
    const blipsRef = useRef<Blip[]>([])
    const initializedRef = useRef(false)

    // Initialize exactly 6 blips - one per threat type
    const initializeBlips = useCallback(() => {
        // Only initialize once, or if we have no blips
        if (initializedRef.current && blipsRef.current.length === 6) {
            // Update values but keep positions
            blipsRef.current.forEach((blip) => {
                const threat = THREATS.find(t => t.key === blip.threatKey)
                if (threat) {
                    const value = data[threat.key as keyof ThreatData] as number
                    blip.value = value
                    blip.label = `${threat.label}-${value}`
                }
            })
            return
        }

        const newBlips: Blip[] = []

        // Distribute 6 blips evenly around the radar - coming from all directions
        THREATS.forEach((threat, index) => {
            const value = data[threat.key as keyof ThreatData] as number
            // Space blips evenly around the circle (60 degrees apart)
            // Start at different positions so they're well spread out
            const baseAngle = (index / 6) * Math.PI * 2
            // Small random offset to avoid perfect symmetry, but keep them spread
            const angle = baseAngle + (Math.random() - 0.5) * 0.3

            newBlips.push({
                threatKey: threat.key,
                angle: angle,
                distance: 0.5 + Math.random() * 0.4, // Random distance (0.5 to 0.9 of radius)
                targetDistance: 0, // Target is always center
                label: `${threat.label}-${value}`,
                color: threat.color,
                value: value,
            })
        })

        blipsRef.current = newBlips
        initializedRef.current = true
    }, [data])

    // Initialize blips when data changes
    useEffect(() => {
        initializeBlips()
    }, [data, initializeBlips])

    const draw = useCallback(() => {
        const canvas = canvasRef.current
        if (!canvas) return

        const ctx = canvas.getContext("2d")
        if (!ctx) return

        const dpr = window.devicePixelRatio || 1
        const rect = canvas.getBoundingClientRect()

        canvas.width = rect.width * dpr
        canvas.height = rect.height * dpr
        ctx.scale(dpr, dpr)

        const centerX = rect.width / 2
        const centerY = rect.height / 2
        const maxRadius = Math.min(centerX, centerY) - 15

        // Clear canvas with dark background
        ctx.fillStyle = "#0a0f14"
        ctx.fillRect(0, 0, rect.width, rect.height)

        // Draw radar grid (concentric circles)
        const rings = 5
        for (let i = 1; i <= rings; i++) {
            const radius = (maxRadius / rings) * i
            ctx.beginPath()
            ctx.arc(centerX, centerY, radius, 0, Math.PI * 2)
            ctx.strokeStyle = "rgba(34, 197, 94, 0.12)"
            ctx.lineWidth = 1
            ctx.stroke()
        }

        // Draw radial lines (12 lines like a clock)
        for (let i = 0; i < 12; i++) {
            const angle = (i / 12) * Math.PI * 2
            ctx.beginPath()
            ctx.moveTo(centerX, centerY)
            ctx.lineTo(
                centerX + Math.cos(angle) * maxRadius,
                centerY + Math.sin(angle) * maxRadius
            )
            ctx.strokeStyle = "rgba(34, 197, 94, 0.08)"
            ctx.lineWidth = 1
            ctx.stroke()
        }

        // Draw sweep line (rotating radar beam)
        sweepAngleRef.current += 0.012
        const sweepAngle = sweepAngleRef.current % (Math.PI * 2)

        // Sweep trail gradient (wider, more visible)
        const trailLength = 0.6 // radians
        for (let i = 0; i < 30; i++) {
            const trailAngle = sweepAngle - (i / 30) * trailLength
            const alpha = (1 - i / 30) * 0.25
            ctx.beginPath()
            ctx.moveTo(centerX, centerY)
            ctx.lineTo(
                centerX + Math.cos(trailAngle) * maxRadius,
                centerY + Math.sin(trailAngle) * maxRadius
            )
            ctx.strokeStyle = `rgba(34, 197, 94, ${alpha})`
            ctx.lineWidth = 1.5
            ctx.stroke()
        }

        // Main sweep line
        ctx.beginPath()
        ctx.moveTo(centerX, centerY)
        ctx.lineTo(
            centerX + Math.cos(sweepAngle) * maxRadius,
            centerY + Math.sin(sweepAngle) * maxRadius
        )
        ctx.strokeStyle = "rgba(34, 197, 94, 0.7)"
        ctx.lineWidth = 2
        ctx.stroke()

        // Update and draw blips - only 6 blips, move only when sweep passes
        // Center circle radius as fraction of maxRadius (30px center circle)
        const centerCircleRadius = 30 / maxRadius

        blipsRef.current.forEach((blip) => {
            // Normalize blip angle to 0-2π
            let blipAngle = blip.angle % (Math.PI * 2)
            if (blipAngle < 0) blipAngle += Math.PI * 2

            // Check if sweep just passed over this blip (within a small arc)
            const sweepTolerance = 0.15 // radians - how close sweep needs to be
            let angleDiff = sweepAngle - blipAngle
            // Normalize angle difference
            while (angleDiff > Math.PI) angleDiff -= Math.PI * 2
            while (angleDiff < -Math.PI) angleDiff += Math.PI * 2

            // If sweep just passed (within tolerance and sweep is ahead)
            if (angleDiff > 0 && angleDiff < sweepTolerance) {
                // Move very slowly toward center - never backwards
                const moveSpeed = 0.003 // Very slow movement toward center
                blip.distance -= moveSpeed

                // Check if reached center circle (touched the grade)
                if (blip.distance <= centerCircleRadius + 0.08) {
                    // Reset to outer position - find angle that's far from other blips
                    blip.distance = 0.8 + Math.random() * 0.15 // Reset to 0.8-0.95

                    // Find the largest gap between existing blips and place there
                    const otherAngles = blipsRef.current
                        .filter(b => b.threatKey !== blip.threatKey)
                        .map(b => b.angle % (Math.PI * 2))
                        .sort((a, b) => a - b)

                    if (otherAngles.length > 0) {
                        // Find largest gap
                        let maxGap = 0
                        let gapStart = 0
                        for (let i = 0; i < otherAngles.length; i++) {
                            const next = (i + 1) % otherAngles.length
                            let gap = otherAngles[next] - otherAngles[i]
                            if (next === 0) gap = (Math.PI * 2 - otherAngles[i]) + otherAngles[0]
                            if (gap > maxGap) {
                                maxGap = gap
                                gapStart = otherAngles[i]
                            }
                        }
                        // Place in middle of largest gap with small random offset
                        blip.angle = gapStart + maxGap / 2 + (Math.random() - 0.5) * 0.3
                    } else {
                        blip.angle = Math.random() * Math.PI * 2
                    }
                }
            }

            const blipX = centerX + Math.cos(blip.angle) * (blip.distance * maxRadius)
            const blipY = centerY + Math.sin(blip.angle) * (blip.distance * maxRadius)

            // Only draw if value > 0
            if (blip.value === 0) return

            // Draw triangle pointing toward center
            const triangleSize = 8
            const pointAngle = blip.angle + Math.PI // Point toward center

            ctx.beginPath()
            ctx.moveTo(
                blipX + Math.cos(pointAngle) * triangleSize * 1.4,
                blipY + Math.sin(pointAngle) * triangleSize * 1.4
            )
            ctx.lineTo(
                blipX + Math.cos(pointAngle + 2.4) * triangleSize,
                blipY + Math.sin(pointAngle + 2.4) * triangleSize
            )
            ctx.lineTo(
                blipX + Math.cos(pointAngle - 2.4) * triangleSize,
                blipY + Math.sin(pointAngle - 2.4) * triangleSize
            )
            ctx.closePath()
            ctx.fillStyle = blip.color
            ctx.fill()

            // Draw label below blip
            const labelOffsetX = 0
            const labelOffsetY = 16

            ctx.font = "bold 9px monospace"
            const textWidth = ctx.measureText(blip.label).width

            // Label background
            ctx.fillStyle = "rgba(10, 15, 20, 0.9)"
            ctx.fillRect(
                blipX + labelOffsetX - textWidth / 2 - 3,
                blipY + labelOffsetY - 6,
                textWidth + 6,
                12
            )

            // Label text
            ctx.fillStyle = blip.color
            ctx.textAlign = "center"
            ctx.textBaseline = "middle"
            ctx.fillText(blip.label, blipX + labelOffsetX, blipY + labelOffsetY)
        })

        // Draw center circle with grade
        const grade = getGrade(data.overallScore)

        // Center glow
        const centerGlow = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, 45)
        centerGlow.addColorStop(0, `${grade.color}15`)
        centerGlow.addColorStop(1, "transparent")
        ctx.beginPath()
        ctx.arc(centerX, centerY, 45, 0, Math.PI * 2)
        ctx.fillStyle = centerGlow
        ctx.fill()

        // Center circle
        ctx.beginPath()
        ctx.arc(centerX, centerY, 30, 0, Math.PI * 2)
        ctx.fillStyle = "#0a0f14"
        ctx.fill()
        ctx.strokeStyle = grade.color
        ctx.lineWidth = 2
        ctx.stroke()

        // Grade letter
        ctx.font = "bold 20px monospace"
        ctx.fillStyle = grade.color
        ctx.textAlign = "center"
        ctx.textBaseline = "middle"
        ctx.fillText(grade.letter, centerX, centerY - 2)

        // Score below
        ctx.font = "8px monospace"
        ctx.fillStyle = "rgba(148, 163, 184, 0.7)"
        ctx.fillText(`${data.overallScore}%`, centerX, centerY + 12)

        // Continue animation
        animationRef.current = requestAnimationFrame(draw)
    }, [data])

    useEffect(() => {
        draw()
        return () => {
            if (animationRef.current) {
                cancelAnimationFrame(animationRef.current)
            }
        }
    }, [draw])

    // Handle resize
    useEffect(() => {
        const handleResize = () => {
            if (animationRef.current) {
                cancelAnimationFrame(animationRef.current)
            }
            draw()
        }
        window.addEventListener("resize", handleResize)
        return () => window.removeEventListener("resize", handleResize)
    }, [draw])

    return (
        <Card className="h-full bg-[#0a0f14] border-green-900/30">
            <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                    <CardTitle className="text-lg font-semibold flex items-center gap-2 text-green-500">
                        <Eye className="h-5 w-5" />
                        Threat Visibility
                    </CardTitle>
                    <div className="flex items-center gap-1.5 text-green-500 text-xs font-mono">
                        <span className="relative flex h-2 w-2">
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                        </span>
                        ACTIVE
                    </div>
                </div>
            </CardHeader>
            <CardContent className="p-3">
                <div className="flex gap-3">
                    {/* Radar Screen - Larger */}
                    <div className="flex-1">
                        <div className="relative aspect-square max-h-[340px] mx-auto">
                            <canvas
                                ref={canvasRef}
                                className="w-full h-full rounded-lg"
                                style={{ width: "100%", height: "100%" }}
                            />
                        </div>
                    </div>

                    {/* Legend - Stacked on right */}
                    <div className="flex flex-col justify-end gap-1 w-24 pb-2">
                        {THREATS.map((threat) => {
                            const value = data[threat.key as keyof ThreatData] as number
                            return (
                                <Link
                                    key={threat.key}
                                    href={threat.link}
                                    className={cn(
                                        "flex items-center gap-1.5 px-2 py-1.5 rounded transition-all font-mono",
                                        "hover:bg-green-500/10 cursor-pointer border border-transparent hover:border-green-500/30",
                                        value > 0 ? "opacity-100" : "opacity-30"
                                    )}
                                >
                                    <div
                                        className="w-0 h-0 border-l-[4px] border-l-transparent border-r-[4px] border-r-transparent border-b-[6px] shrink-0"
                                        style={{ borderBottomColor: threat.color }}
                                    />
                                    <div className="min-w-0 flex-1">
                                        <div className="text-[9px] text-muted-foreground truncate">{threat.fullLabel}</div>
                                        <div className="text-xs font-bold" style={{ color: threat.color }}>{value.toLocaleString()}</div>
                                    </div>
                                </Link>
                            )
                        })}
                    </div>
                </div>
            </CardContent>
        </Card>
    )
}
