import * as core from "@actions/core"
import { Config } from "./transformerTypes.js"
import { transformManifest } from "./transformer.js"

/**
 * The main function for the action.
 *
 * @returns Resolves when the action is complete.
 */
export async function run(): Promise<void> {
    try {
        const manifestPath = core.getInput("manifestPath", { required: true })
        const outputPath = core.getInput("outputPath", { required: true })

        const serverHost = core.getInput("webappHost", { required: true })
        const serverPort = core.getInput("webappPort", { required: false })
        const serverPath = normalizeServerPath(
            core.getInput("webappPath", { required: true })
        )

        const azureAppId = core.getInput("azureAppId", { required: false })
        const azureAppUri = core.getInput("azureAppUri", { required: false })

        const config: Config = {
            manifestPath,
            outputPath,
            serverHost,
            serverPort,
            serverPath,
            azureAppId,
            azureAppUri
        }

        await transformManifest(config)

        // Set outputs for other workflow steps to use
        core.setOutput("outputPath", config.outputPath)
    } catch (error) {
        // Fail the workflow run if an error occurs
        if (error instanceof Error) core.setFailed(error.message)
    }
}

function normalizeServerPath(serverPath: string) {
    let path = serverPath

    // Ensure starting slash
    if (!path.startsWith("/")) {
        path = `/${path}`
    }

    // Remove trailing slash
    if (path.endsWith("/")) {
        path = path.slice(0, -1)
    }

    return path
}
