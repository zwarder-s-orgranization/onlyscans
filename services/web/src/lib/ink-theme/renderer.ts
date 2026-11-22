import { createNoiseTexture } from "./noiseTexture";
import { createProgram, type InkProgram } from "./program";
import { FULLSCREEN_VERT, INK_FRAG } from "./shaders";

export type ThemeMode = "light" | "dark";

export interface InkParams {
  duration: number;
  tendril: number;
  noiseScale: number;
  softness: number;
  drift: number;
}

export const INK_PARAMS: InkParams = {
  duration: 1.25,
  tendril: 1.05,
  noiseScale: 1.0,
  softness: 1.4,
  drift: 1.0,
};

export const RIM_COLOR: Record<ThemeMode, [number, number, number]> = {
  dark: [0.02, 0.03, 0.06],
  light: [0.99, 0.995, 1.0],
};

export interface InkFrame {
  to: ThemeMode;
  center: { x: number; y: number };
  radius: number;
  cleanup: number;
  time: number;
  seed: { x: number; y: number; angle: number };
}

export class InkRenderer {
  readonly canvas: HTMLCanvasElement;
  readonly maxTextureSize: number;

  private readonly gl: WebGL2RenderingContext;
  private program!: InkProgram;
  private vao!: WebGLVertexArrayObject;
  private noise!: WebGLTexture;
  private fromTexture: WebGLTexture | null = null;
  private fromWidth = 1;
  private fromHeight = 1;
  private canvasScale = 1;
  private lost = false;

  static create(canvas: HTMLCanvasElement): InkRenderer | null {
    const gl = canvas.getContext("webgl2", {
      alpha: true,
      antialias: false,
      depth: false,
      stencil: false,
      premultipliedAlpha: true,
      preserveDrawingBuffer: false,
      powerPreference: "high-performance",
    });
    if (!gl) return null;
    try {
      return new InkRenderer(canvas, gl);
    } catch (err) {
      console.error("[ink-theme] WebGL2 init failed:", err);
      return null;
    }
  }

  private constructor(canvas: HTMLCanvasElement, gl: WebGL2RenderingContext) {
    this.canvas = canvas;
    this.gl = gl;
    this.maxTextureSize = gl.getParameter(gl.MAX_TEXTURE_SIZE) as number;
    this.init();
  }

  private init(): void {
    const gl = this.gl;
    this.program = createProgram(gl, FULLSCREEN_VERT, INK_FRAG);
    const vao = gl.createVertexArray();
    if (!vao) throw new Error("Failed to create WebGL2 VAO");
    this.vao = vao;
    this.noise = createNoiseTexture(gl);
    this.fromTexture = null;
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
    gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false);
    gl.pixelStorei(gl.UNPACK_COLORSPACE_CONVERSION_WEBGL, gl.NONE);
  }

  watchContext(onLost: () => void, onRestored: () => void): () => void {
    const handleLost = (e: Event) => {
      e.preventDefault();
      this.lost = true;
      this.fromTexture = null;
      onLost();
    };
    const handleRestored = () => {
      this.lost = false;
      this.init();
      onRestored();
    };
    this.canvas.addEventListener("webglcontextlost", handleLost);
    this.canvas.addEventListener("webglcontextrestored", handleRestored);
    return () => {
      this.canvas.removeEventListener("webglcontextlost", handleLost);
      this.canvas.removeEventListener("webglcontextrestored", handleRestored);
    };
  }

  get isLost(): boolean {
    return this.lost;
  }

  resize(scale: number): void {
    const cssW = document.documentElement.clientWidth || window.innerWidth;
    const cssH = document.documentElement.clientHeight || window.innerHeight;
    this.canvas.style.width = `${cssW}px`;
    this.canvas.style.height = `${cssH}px`;
    const w = Math.max(1, Math.round(cssW * scale));
    const h = Math.max(1, Math.round(cssH * scale));
    if (this.canvas.width !== w) this.canvas.width = w;
    if (this.canvas.height !== h) this.canvas.height = h;
    this.canvasScale = cssW > 0 ? w / cssW : scale;
  }

  /** Aligns the overlay CSS box and WebGL backing buffer 1:1 with the captured snapshot. */
  syncToSnapshot(source: HTMLCanvasElement, cssW: number, cssH: number): void {
    this.canvas.style.width = `${cssW}px`;
    this.canvas.style.height = `${cssH}px`;
    const w = Math.max(1, source.width);
    const h = Math.max(1, source.height);
    if (this.canvas.width !== w) this.canvas.width = w;
    if (this.canvas.height !== h) this.canvas.height = h;
    this.canvasScale = cssW > 0 ? w / cssW : 1;
  }

  uploadFrom(source: HTMLCanvasElement): void {
    if (this.lost) return;
    const gl = this.gl;
    if (!this.fromTexture) {
      const tex = gl.createTexture();
      if (!tex) throw new Error("Failed to create WebGL2 snapshot texture");
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      this.fromTexture = tex;
    }
    gl.bindTexture(gl.TEXTURE_2D, this.fromTexture);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, gl.RGBA, gl.UNSIGNED_BYTE, source);
    this.fromWidth = source.width;
    this.fromHeight = source.height;
  }

  clear(): void {
    if (this.lost) return;
    const gl = this.gl;
    gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
  }

  draw(frame: InkFrame): void {
    if (this.lost || !this.fromTexture) return;
    const gl = this.gl;
    const { program, uniform } = this.program;

    gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    gl.useProgram(program);
    gl.bindVertexArray(this.vao);

    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.fromTexture);
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, this.noise);

    gl.uniform1i(uniform("uFrom"), 0);
    gl.uniform1i(uniform("uNoise"), 1);
    gl.uniform2f(uniform("uFromSize"), this.fromWidth, this.fromHeight);
    gl.uniform1f(uniform("uCanvasScale"), this.canvasScale);
    gl.uniform2f(uniform("uRes"), this.canvas.width, this.canvas.height);

    gl.uniform2f(uniform("uCenter"), frame.center.x, frame.center.y);
    gl.uniform1f(uniform("uRadius"), frame.radius);
    gl.uniform1f(uniform("uCleanup"), frame.cleanup);
    gl.uniform1f(uniform("uTime"), frame.time);
    gl.uniform1f(
      uniform("uRef"),
      Math.max(this.canvas.width, this.canvas.height) / this.canvasScale,
    );
    gl.uniform2f(uniform("uSeed"), frame.seed.x, frame.seed.y);

    const cos = Math.cos(frame.seed.angle);
    const sin = Math.sin(frame.seed.angle);
    gl.uniformMatrix2fv(uniform("uSeedRot"), false, [cos, sin, -sin, cos]);

    gl.uniform1f(uniform("uTendril"), INK_PARAMS.tendril);
    gl.uniform1f(uniform("uNoiseScale"), INK_PARAMS.noiseScale);
    gl.uniform1f(uniform("uSoftness"), INK_PARAMS.softness);
    gl.uniform1f(uniform("uDrift"), INK_PARAMS.drift);
    gl.uniform3fv(uniform("uRimColor"), RIM_COLOR[frame.to]);

    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }

  dispose(): void {
    if (this.lost) return;
    const gl = this.gl;
    if (this.fromTexture) gl.deleteTexture(this.fromTexture);
    gl.deleteTexture(this.noise);
    gl.deleteVertexArray(this.vao);
    gl.deleteProgram(this.program.program);
  }
}
