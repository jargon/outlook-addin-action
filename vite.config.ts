/// <reference types="vitest/config" />
import { defineConfig } from "vite"
import { builtinModules } from "node:module"

const NODE_BUILT_IN_MODULES = builtinModules.filter((m) => !m.startsWith("_"))
NODE_BUILT_IN_MODULES.push(...NODE_BUILT_IN_MODULES.map((m) => `node:${m}`))

export default defineConfig({
    optimizeDeps: {
        exclude: NODE_BUILT_IN_MODULES
    },
    build: {
        target: "node20",
        lib: {
            entry: "src/index.ts",
            formats: ["es"],
            fileName: () => "index.js"
        },
        sourcemap: true,
        rollupOptions: {
            external: NODE_BUILT_IN_MODULES, // Add external dependencies if needed
            output: {
                esModule: true
            }
        }
    },
    test: {
        globals: true,
        environment: "node",
        exclude: ["dist", "node_modules"],
        clearMocks: true,
        coverage: {
            enabled: true,
            reportsDirectory: "./coverage",
            reporter: ["json-summary", "text", "lcov"],
            include: ["./src/**"],
            exclude: ["dist", "node_modules"]
        }
    },
    resolve: {
        // Vite uses ES module resolution by default
        conditions: ["node"],
        mainFields: ["module", "main"],
        preserveSymlinks: true,
        extensions: [".ts", ".js"]
    }
})
