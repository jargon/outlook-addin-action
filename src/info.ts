import * as core from "@actions/core"
import { Manifest, WebApplicationInfo } from "./manifestTypes.js"
import { PathConfig } from "./transformerTypes.js"
import { getDisplayName } from "./manifestReader.js"

export function printPathInfo(config: PathConfig) {
    core.info(`Transforming manifest`)
    core.info(`    from: ${config.manifestPath}`)
    core.info(`      to: ${config.outputPath}`)
}

export function printAddinInfo(manifest: Manifest) {
    const app = manifest.OfficeApp
    const displayName = getDisplayName(manifest)
    core.info(`Transforming Outlook web addin:`)
    core.info(`    ID: ${app.Id}`)
    core.info(`    Name: ${displayName.$.DefaultValue}`)
}

export function printAzureInfo(webappInfo: WebApplicationInfo) {
    core.info(`Azure info:`)
    core.info(`    Application ID: ${webappInfo.Id}`)
    core.info(`    App ID URL: ${webappInfo.Resource}`)
}

export function printUrlTransform(from: string, to: string) {
    core.info(`    ${from}`)
    core.info(`        -> ${to}`)
}
