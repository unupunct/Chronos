# Generates Assets\chronos.ico for Chronos - Windows Timeline.
# Draws a clock face with a rewind/history arc on a dark rounded-square
# background (matching the app's dark Fluent palette) and packs
# 16/32/48/128/256 px PNG frames into a single .ico container.
# ASCII-only, PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$outDir = Join-Path $PSScriptRoot '..\Assets'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$icoPath = Join-Path $outDir 'chronos.ico'

function New-FramePng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)

    $bg     = [System.Drawing.Color]::FromArgb(255, 15, 20, 32)   # #0F1420 app background
    $bg2    = [System.Drawing.Color]::FromArgb(255, 22, 29, 46)   # #161D2E app panel
    $accent = [System.Drawing.Color]::FromArgb(255, 78, 161, 255) # #4EA1FF accent blue
    $good   = [System.Drawing.Color]::FromArgb(255, 63, 212, 138) # #3FD48A success green
    $dim    = [System.Drawing.Color]::FromArgb(255, 90, 107, 128) # #5A6B80 faint text
    $white  = [System.Drawing.Color]::FromArgb(255, 228, 236, 247)

    # rounded-square background with a subtle diagonal gradient
    $rectX = 0
    $rectY = 0
    $rectW = $size
    $rectH = $size
    $rect = New-Object System.Drawing.Rectangle
    $rect.X = $rectX; $rect.Y = $rectY; $rect.Width = $rectW; $rect.Height = $rectH

    $r = [Math]::Max(2, [int]($size * 0.20))
    $d = $r * 2
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($rect.X, $rect.Y, $d, $d, 180, 90)
    $path.AddArc(($rect.Right - $d), $rect.Y, $d, $d, 270, 90)
    $path.AddArc(($rect.Right - $d), ($rect.Bottom - $d), $d, $d, 0, 90)
    $path.AddArc($rect.X, ($rect.Bottom - $d), $d, $d, 90, 90)
    $path.CloseFigure()

    $pt1 = New-Object System.Drawing.Point
    $pt1.X = $rect.X; $pt1.Y = $rect.Y
    $pt2 = New-Object System.Drawing.Point
    $pt2.X = $rect.Right; $pt2.Y = $rect.Bottom
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($pt1, $pt2, $bg2, $bg)
    $g.FillPath($grad, $path)

    $cx = $size / 2.0
    $cy = $size / 2.0
    $clockR = $size * 0.315

    # clock face ring
    $ringW = [Math]::Max(2.0, $size * 0.058)
    $ringPen = New-Object System.Drawing.Pen($accent, $ringW)
    $ringPen.StartCap = 'Round'; $ringPen.EndCap = 'Round'
    $ringRect = New-Object System.Drawing.RectangleF(($cx - $clockR), ($cy - $clockR), ($clockR * 2), ($clockR * 2))
    $g.DrawEllipse($ringPen, $ringRect)

    # 12/3/6/9 tick marks (only worth drawing above 32px)
    if ($size -ge 48) {
        $tickPen = New-Object System.Drawing.Pen($dim, [Math]::Max(1.0, $size * 0.02))
        $tickLen = $clockR * 0.16
        foreach ($ang in @(0, 90, 180, 270)) {
            $rad = $ang * [Math]::PI / 180.0
            $ox = [Math]::Sin($rad); $oy = -[Math]::Cos($rad)
            $x1 = $cx + $ox * ($clockR - $ringW)
            $y1 = $cy + $oy * ($clockR - $ringW)
            $x2 = $cx + $ox * ($clockR - $ringW - $tickLen)
            $y2 = $cy + $oy * ($clockR - $ringW - $tickLen)
            $g.DrawLine($tickPen, $x1, $y1, $x2, $y2)
        }
    }

    # clock hands: hour hand to ~11, minute hand to ~2 (a purposeful, slightly
    # asymmetric time so the icon reads as "a clock", not a plus sign).
    # Below 24px thin double hands blur into a smudge, so draw one bold hand only.
    $handBrush = New-Object System.Drawing.SolidBrush($white)
    $hourAngle = -60.0   # ~11 o'clock
    $minAngle  = 55.0    # ~2 o'clock
    $hourLen = $clockR * 0.52
    $minLen  = $clockR * 0.78
    $hRad = $hourAngle * [Math]::PI / 180.0
    $mRad = $minAngle  * [Math]::PI / 180.0

    if ($size -le 24) {
        $boldPen = New-Object System.Drawing.Pen($white, [Math]::Max(2.4, $size * 0.16))
        $boldPen.StartCap = 'Round'; $boldPen.EndCap = 'Round'
        $boldLen = $clockR * 0.72
        $g.DrawLine($boldPen, $cx, $cy, ($cx + [Math]::Sin($mRad) * $boldLen), ($cy - [Math]::Cos($mRad) * $boldLen))
    }
    else {
        $hourPen = New-Object System.Drawing.Pen($white, [Math]::Max(2.2, $size * 0.062))
        $hourPen.StartCap = 'Round'; $hourPen.EndCap = 'Round'
        $minPen = New-Object System.Drawing.Pen($white, [Math]::Max(1.8, $size * 0.048))
        $minPen.StartCap = 'Round'; $minPen.EndCap = 'Round'
        $g.DrawLine($hourPen, $cx, $cy, ($cx + [Math]::Sin($hRad) * $hourLen), ($cy - [Math]::Cos($hRad) * $hourLen))
        $g.DrawLine($minPen,  $cx, $cy, ($cx + [Math]::Sin($mRad) * $minLen),  ($cy - [Math]::Cos($mRad) * $minLen))
    }

    # center pivot
    $pivotR = [Math]::Max(1.0, $size * 0.028)
    $g.FillEllipse($handBrush, ($cx - $pivotR), ($cy - $pivotR), ($pivotR * 2), ($pivotR * 2))

    # rewind/history arc + arrowhead, wrapping the bottom-right of the ring
    # (only above 32px - it turns to mud at small sizes)
    if ($size -ge 48) {
        $arcR = $clockR + $ringW * 1.6
        $arcPen = New-Object System.Drawing.Pen($good, [Math]::Max(1.4, $size * 0.045))
        $arcPen.StartCap = 'Round'; $arcPen.EndCap = 'Round'
        $arcRect = New-Object System.Drawing.RectangleF(($cx - $arcR), ($cy - $arcR), ($arcR * 2), ($arcR * 2))
        $startDeg = 20.0
        $sweepDeg = 95.0
        $g.DrawArc($arcPen, $arcRect, $startDeg, $sweepDeg)

        # arrowhead at the arc's tail (startDeg end), pointing tangentially
        $endDeg = $startDeg
        $rad = $endDeg * [Math]::PI / 180.0
        $tipX = $cx + [Math]::Cos($rad) * $arcR
        $tipY = $cy + [Math]::Sin($rad) * $arcR
        $tanRad = $rad - [Math]::PI / 2.0   # tangent direction
        $ah = $size * 0.10
        $perpRad = $tanRad + [Math]::PI / 2.0
        $baseX = $tipX - [Math]::Cos($tanRad) * $ah
        $baseY = $tipY - [Math]::Sin($tanRad) * $ah
        $p1 = New-Object System.Drawing.PointF($tipX, $tipY)
        $p2 = New-Object System.Drawing.PointF(($baseX + [Math]::Cos($perpRad) * $ah * 0.55), ($baseY + [Math]::Sin($perpRad) * $ah * 0.55))
        $p3 = New-Object System.Drawing.PointF(($baseX - [Math]::Cos($perpRad) * $ah * 0.55), ($baseY - [Math]::Sin($perpRad) * $ah * 0.55))
        $goodBrush = New-Object System.Drawing.SolidBrush($good)
        $g.FillPolygon($goodBrush, @($p1, $p2, $p3))
    }

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$sizes = @(16, 32, 48, 128, 256)
$frames = @()
foreach ($s in $sizes) { $frames += ,(New-FramePng $s) }

# ---- Pack ICO container (PNG frames, valid on Windows Vista+) ----
$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)
$bw.Write([UInt16]0)                # reserved
$bw.Write([UInt16]1)                # type: icon
$bw.Write([UInt16]$sizes.Count)     # image count

$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $len = $frames[$i].Length
    $bw.Write([Byte]($(if ($s -ge 256) { 0 } else { $s })))  # width  (0 = 256)
    $bw.Write([Byte]($(if ($s -ge 256) { 0 } else { $s })))  # height
    $bw.Write([Byte]0)              # palette colors
    $bw.Write([Byte]0)              # reserved
    $bw.Write([UInt16]1)            # planes
    $bw.Write([UInt16]32)           # bpp
    $bw.Write([UInt32]$len)         # data size
    $bw.Write([UInt32]$offset)      # data offset
    $offset += $len
}
foreach ($f in $frames) { $bw.Write($f) }
$bw.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $ms.ToArray())
$bw.Dispose(); $ms.Dispose()

Write-Output ("Icon written: {0} ({1} bytes)" -f $icoPath, (Get-Item $icoPath).Length)
