"use client";

import { useMutation } from "@tanstack/react-query";
import jsQR from "jsqr";
import { Camera, ImageUp, QrCode, ScanLine, Square } from "lucide-react";
import QRCode from "qrcode";
import { useCallback, useEffect, useRef, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ScanResultView } from "@/components/scan/scan-result";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, LoadingState, Notice } from "@/components/ui/states";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

const SAMPLES = [
  { label: "Parking-meter sticker", payload: "http://parking-pay.city-fines.example/pay?plate=KA01&amount=499" },
  { label: "Restaurant menu", payload: "https://paypa1-checkout.xyz/menu/table12" },
  { label: "Genuine link", payload: "https://www.wikipedia.org/" },
];

function decodeFromImage(img: CanvasImageSource, w: number, h: number): string | null {
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  ctx.drawImage(img, 0, 0, w, h);
  const data = ctx.getImageData(0, 0, w, h);
  return jsQR(data.data, w, h, { inversionAttempts: "attemptBoth" })?.data ?? null;
}

function SampleQr({ label, payload, onScan }: { label: string; payload: string; onScan: (text: string) => void }) {
  const [src, setSrc] = useState<string>("");
  useEffect(() => {
    QRCode.toDataURL(payload, { margin: 1, width: 180, color: { dark: "#0a1020", light: "#ffffff" } }).then(setSrc);
  }, [payload]);
  const scan = () => {
    const img = new Image();
    img.onload = () => {
      const text = decodeFromImage(img, img.width, img.height);
      if (text) onScan(text);
    };
    img.src = src;
  };
  return (
    <button type="button" onClick={scan} disabled={!src}
            className="group flex flex-col items-center gap-2 rounded-xl border border-border bg-surface-2 p-3 transition hover:-translate-y-0.5 hover:border-accent/50">
      {/* eslint-disable-next-line @next/next/no-img-element -- generated data URL */}
      {src ? <img src={src} alt={`Sample QR code: ${label}`} className="size-32 rounded-md" /> : <div className="size-32" />}
      <span className="text-xs text-muted group-hover:text-fg">{label}</span>
      <span className="text-[10px] text-accent">Click to scan</span>
    </button>
  );
}

export default function QrScannerPage() {
  const [decoded, setDecoded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [camera, setCamera] = useState(false);
  const [dragging, setDragging] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const scan = useMutation({ mutationFn: api.scanUrl });

  const handlePayload = useCallback(
    (text: string) => {
      setDecoded(text);
      setError(null);
      if (/^(https?:\/\/|www\.)/i.test(text.trim()) || /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/|$)/i.test(text.trim())) {
        scan.mutate({ url: text.trim(), use_llm: false });
      } else {
        scan.reset();
        setError("This QR code does not contain a web link, so there is nothing to analyze as a URL.");
      }
    },
    [scan],
  );

  const stopCamera = useCallback(() => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    setCamera(false);
  }, []);

  useEffect(() => () => stopCamera(), [stopCamera]);

  useEffect(() => {
    if (!camera) return;
    let raf = 0;
    const tick = () => {
      const v = videoRef.current;
      if (v && v.readyState >= 2 && v.videoWidth) {
        const text = decodeFromImage(v, v.videoWidth, v.videoHeight);
        if (text) {
          stopCamera();
          handlePayload(text);
          return;
        }
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [camera, handlePayload, stopCamera]);

  const startCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      streamRef.current = stream;
      setCamera(true);
      requestAnimationFrame(() => {
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          void videoRef.current.play();
        }
      });
    } catch {
      setError("Camera not available. Upload an image of the QR code instead.");
    }
  };

  const readFile = (file: File | undefined) => {
    if (!file || !file.type.startsWith("image/")) return setError("Please choose an image file.");
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const scale = Math.min(1, 1200 / Math.max(img.width, img.height));
      const text = decodeFromImage(img, Math.round(img.width * scale), Math.round(img.height * scale));
      URL.revokeObjectURL(url);
      if (text) handlePayload(text);
      else setError("No QR code found in that image. Try a sharper or closer photo.");
    };
    img.src = url;
  };

  return (
    <>
      <PageHeader
        title="QR code scanner"
        description="“Quishing” hides phishing links inside QR codes on parking meters, menus and posters, where you can't read the address. Scan it here first: the QR is decoded in your browser and the link is analyzed without being opened."
      />
      <div className="flex flex-col gap-6">
        <div className="grid gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ScanLine className="size-4 text-accent" aria-hidden /> Scan a QR code</CardTitle>
              <CardDescription>Use your camera, drop a screenshot, or paste an image (Ctrl+V).</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <label
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => { e.preventDefault(); setDragging(false); readFile(e.dataTransfer.files[0]); }}
                onPaste={(e) => readFile(Array.from(e.clipboardData.files)[0])}
                tabIndex={0}
                className={cn("flex min-h-44 cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed p-6 text-center transition",
                  dragging ? "border-accent bg-accent/10" : "border-border-strong hover:border-accent/60")}
              >
                {camera ? (
                  <video ref={videoRef} muted playsInline className="max-h-64 rounded-lg" />
                ) : (
                  <>
                    <ImageUp className="size-8 text-muted" aria-hidden />
                    <span className="text-sm">Drop a QR image here or click to choose</span>
                    <span className="text-[11px] text-subtle">Decoded locally — the image never leaves your device</span>
                  </>
                )}
                <input type="file" accept="image/*" className="sr-only" onChange={(e) => readFile(e.target.files?.[0])} />
              </label>
              {camera ? (
                <Button variant="outline" onClick={stopCamera}><Square aria-hidden /> Stop camera</Button>
              ) : (
                <Button variant="secondary" onClick={startCamera}><Camera aria-hidden /> Use camera</Button>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><QrCode className="size-4 text-accent" aria-hidden /> Try a sample</CardTitle>
              <CardDescription>Synthetic QR codes generated in your browser — click one to scan it.</CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-3 gap-3">
              {SAMPLES.map((s) => <SampleQr key={s.label} {...s} onScan={handlePayload} />)}
            </CardContent>
          </Card>
        </div>

        {decoded && (
          <Notice>
            <span className="text-fg">Decoded content:</span>{" "}
            <code className="break-all">{decoded}</code>
          </Notice>
        )}
        {error && <Notice tone="warning">{error}</Notice>}
        {scan.isPending && <LoadingState label="Analyzing the hidden link…" />}
        {scan.isError && <ErrorState error={scan.error} />}
        {scan.data && !scan.isPending && <ScanResultView result={scan.data} />}
      </div>
    </>
  );
}
