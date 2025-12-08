# Threat Radar Component - LLM Recreation Prompt

## Overview

Create an airport-style radar visualization component for a security dashboard that displays threat categories as triangular blips approaching a central security grade. The component should evoke the aesthetic of an air traffic control tower screen, conveying real-time threat visibility and monitoring.

## Technology Stack

- **Framework**: Next.js 14+ with React
- **Rendering**: HTML5 Canvas API with `requestAnimationFrame` for smooth 60fps animation
- **Styling**: Tailwind CSS with shadcn/ui Card components
- **Language**: TypeScript

## Visual Design Specifications

### Color Palette

| Element | Color | Hex Code |
|---------|-------|----------|
| Background | Dark navy/black | `#0a0f14` |
| Grid lines | Green (low opacity) | `rgba(34, 197, 94, 0.12)` |
| Radial lines | Green (very low opacity) | `rgba(34, 197, 94, 0.08)` |
| Sweep beam | Green | `rgba(34, 197, 94, 0.7)` |
| Sweep trail | Green (gradient fade) | `rgba(34, 197, 94, 0.25)` to `0` |
| Grade A | Green | `#22c55e` |
| Grade B | Lime | `#84cc16` |
| Grade C | Yellow | `#eab308` |
| Grade D | Orange | `#f97316` |
| Grade F | Red | `#ef4444` |

### Threat Category Colors

| Category | Color | Hex Code |
|----------|-------|----------|
| Critical | Red | `#ef4444` |
| High | Orange | `#f97316` |
| Secrets | Purple | `#a855f7` |
| Stale Users | Blue | `#3b82f6` |
| Abandoned | Gray | `#6b7280` |
| Medium | Yellow | `#eab308` |

## Component Structure

### Layout

```
+------------------------------------------+
| [Eye Icon] Threat Visibility    [*] ACTIVE |  <- Header
+------------------------------------------+
|                                    |      |
|                                    | CRIT |
|         [RADAR CANVAS]             | HIGH |  <- Legend
|         max-h: 340px               | SECR |     stacked
|         aspect-ratio: 1:1          | STAL |     on right
|                                    | ABAN |
|                                    | MED  |
+------------------------------------------+
```

### Card Container
- Dark background: `bg-[#0a0f14]`
- Green border: `border-green-900/30`
- Header with Eye icon from lucide-react
- "ACTIVE" indicator with solid green dot (no animation/pulsing)

## Canvas Rendering Details

### Grid System

1. **Concentric Circles (5 rings)**
   - Evenly spaced from center to edge
   - Stroke: `rgba(34, 197, 94, 0.12)`, 1px width
   - Full 360-degree circles

2. **Radial Lines (12 lines)**
   - Like clock hour markers, every 30 degrees
   - Stroke: `rgba(34, 197, 94, 0.08)`, 1px width
   - Extend from center to outer edge

### Sweep Beam Animation

1. **Rotation**
   - Speed: `0.012` radians per frame (~0.7 degrees/frame)
   - Direction: Clockwise
   - Continuous rotation using `requestAnimationFrame`

2. **Trail Effect**
   - Length: `0.6` radians (~34 degrees)
   - 30 gradient steps fading from `alpha=0.25` to `alpha=0`
   - Line width: 1.5px

3. **Main Beam**
   - Stroke: `rgba(34, 197, 94, 0.7)`
   - Line width: 2px

### Blip (Triangle) System

#### Initialization
- Exactly **6 blips** - one per threat category
- Initial positions distributed evenly around the radar (60 degrees apart)
- Small random angular offset (±0.15 radians) to avoid perfect symmetry
- Starting distance: random between 0.5 and 0.9 of radius

#### Triangle Shape
- Size: 8px base dimension
- Points toward center (in direction of movement)
- Filled with threat category color
- Shape calculation:
  ```
  Point angle = blip.angle + PI (toward center)
  Tip: pointAngle * 1.4 * size
  Left: pointAngle + 2.4 radians * size
  Right: pointAngle - 2.4 radians * size
  ```

#### Movement Behavior

**Critical Rule: Triangles ONLY move when the radar sweep passes over them**

1. **Sweep Detection**
   - Tolerance: 0.15 radians
   - Only move when sweep angle is just ahead of blip angle
   - Check: `angleDiff > 0 && angleDiff < sweepTolerance`

2. **Movement Speed**
   - Very slow: `0.003` per sweep pass
   - Always toward center (never backwards)
   - `blip.distance -= moveSpeed`

3. **Reset on Center Touch**
   - Trigger: when distance reaches center circle radius + 0.08
   - Reset distance: random 0.8-0.95 of radius
   - New angle: placed in largest gap between other blips

#### Gap-Finding Algorithm for Reset
```typescript
// Find angles of other 5 blips, sorted
const otherAngles = blips
    .filter(b => b.key !== currentBlip.key)
    .map(b => b.angle % (2*PI))
    .sort()

// Find largest gap
let maxGap = 0, gapStart = 0
for (let i = 0; i < otherAngles.length; i++) {
    const next = (i + 1) % otherAngles.length
    let gap = otherAngles[next] - otherAngles[i]
    if (next === 0) gap = (2*PI - otherAngles[i]) + otherAngles[0]
    if (gap > maxGap) { maxGap = gap; gapStart = otherAngles[i] }
}

// Place in middle of gap
newAngle = gapStart + maxGap/2 + random(-0.15, 0.15)
```

#### Labels
- Position: 16px below triangle center
- Font: `bold 9px monospace`
- Format: `{ABBREV}-{count}` (e.g., "CRIT-176")
- Background: `rgba(10, 15, 20, 0.9)` rounded rectangle
- Text color: matches threat category color

### Center Grade Circle

1. **Glow Effect**
   - Radial gradient from center
   - Color: grade color at 15% opacity fading to transparent
   - Radius: 45px

2. **Circle**
   - Radius: 30px
   - Fill: `#0a0f14` (same as background)
   - Stroke: grade color, 2px width

3. **Grade Letter**
   - Font: `bold 20px monospace`
   - Color: grade color
   - Centered in circle, slightly above center (-2px)

4. **Score Percentage**
   - Font: `8px monospace`
   - Color: `rgba(148, 163, 184, 0.7)`
   - Below grade letter (+12px from center)

### Grade Calculation
```typescript
function getGrade(score: number): { letter: string; color: string } {
    if (score >= 90) return { letter: "A", color: "#22c55e" }
    if (score >= 80) return { letter: "B", color: "#84cc16" }
    if (score >= 70) return { letter: "C", color: "#eab308" }
    if (score >= 60) return { letter: "D", color: "#f97316" }
    return { letter: "F", color: "#ef4444" }
}
```

## Legend Panel

### Layout
- Positioned to the right of the radar
- Stacked vertically
- Width: 24 (w-24 = 96px)
- Aligned to bottom (`justify-end`)

### Legend Items
- Each item is a clickable Link to relevant page
- Contains:
  - Small triangle icon (CSS borders, pointing up)
  - Label (e.g., "Critical", "High")
  - Count value with thousand separators

### Styling
```css
/* Base state */
font-family: monospace;
padding: 0.375rem 0.5rem;
border: 1px solid transparent;
border-radius: 0.25rem;

/* Hover state */
background: rgba(34, 197, 94, 0.1);
border-color: rgba(34, 197, 94, 0.3);

/* Zero value state */
opacity: 0.3;
```

## Data Interface

```typescript
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
```

## Animation Loop Architecture

```typescript
const canvasRef = useRef<HTMLCanvasElement>(null)
const animationRef = useRef<number>()
const sweepAngleRef = useRef(0)
const blipsRef = useRef<Blip[]>([])

const draw = useCallback(() => {
    // 1. Get canvas context
    // 2. Handle DPR scaling
    // 3. Clear and fill background
    // 4. Draw grid (circles + radial lines)
    // 5. Update and draw sweep beam
    // 6. Update blip positions (only if sweep passed)
    // 7. Draw blips and labels
    // 8. Draw center grade circle
    // 9. Request next frame
    animationRef.current = requestAnimationFrame(draw)
}, [data])

useEffect(() => {
    draw()
    return () => cancelAnimationFrame(animationRef.current)
}, [draw])
```

## High-DPI (Retina) Support

```typescript
const dpr = window.devicePixelRatio || 1
const rect = canvas.getBoundingClientRect()

canvas.width = rect.width * dpr
canvas.height = rect.height * dpr
ctx.scale(dpr, dpr)
```

## Resize Handling

```typescript
useEffect(() => {
    const handleResize = () => {
        cancelAnimationFrame(animationRef.current)
        draw()
    }
    window.addEventListener("resize", handleResize)
    return () => window.removeEventListener("resize", handleResize)
}, [draw])
```

## Key Design Principles

1. **Airport Control Tower Aesthetic**: The visualization should feel like monitoring aircraft on approach - professional, technical, and surveillance-oriented.

2. **Minimal Animation**: Avoid flashy effects. The only movements are:
   - Steady radar sweep rotation
   - Slow, deliberate triangle approach (only on sweep)

3. **Information Density**: Each triangle represents a threat category with its count visible. The viewer can quickly assess the threat landscape.

4. **Color Coding**: Severity is immediately apparent through color - red threats demand attention, while gray/blue are lower priority.

5. **Threat Convergence**: Triangles approaching the center grade creates a visual metaphor of threats "closing in" on your security posture.

6. **Spatial Distribution**: Triangles should always appear to come from all directions, never bunched together.

## Performance Considerations

- Use `requestAnimationFrame` for smooth 60fps animation
- Minimize object creation in the draw loop
- Use refs for mutable animation state to avoid re-renders
- Canvas operations are batched per frame

## Dependencies

```json
{
    "lucide-react": "^0.x",
    "@/components/ui/card": "shadcn/ui",
    "@/lib/utils": "cn utility function",
    "next/link": "Next.js routing"
}
```

## Example Usage

```tsx
<ThreatRadar
    data={{
        critical: 176,
        high: 432,
        medium: 891,
        secrets: 23,
        abandoned: 45,
        staleContributors: 12,
        overallScore: 72
    }}
/>
```

## Common Pitfalls to Avoid

1. **Too many triangles**: Always exactly 6, one per category
2. **Continuous movement**: Triangles should ONLY move when sweep passes
3. **Fast movement**: Keep speed very slow (0.003 per pass)
4. **Bunched triangles**: Use gap-finding algorithm on reset
5. **Backward movement**: Triangles only move toward center
6. **Pulsing/flashing effects**: Avoid - they're distracting
7. **Complex gradients**: Keep it simple and clean
