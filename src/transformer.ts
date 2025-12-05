import * as fs from "node:fs/promises"
import * as path from "node:path"
import xml2js from "xml2js"
import * as core from "@actions/core"
import { Manifest, ResourceUrl, WebApplicationInfo } from "./manifestTypes.js"
import {
    AddinConfig,
    AzureConfig,
    Config,
    ServerConfig
} from "./transformerTypes.js"
import {
    printAddinInfo,
    printAzureInfo,
    printPathInfo,
    printUrlTransform
} from "./info.js"
import {
    getAppDomains,
    getIconUrls,
    getResourceImages,
    getResourceUrls,
    getSourceLocations,
    getWebApplicationInfo
} from "./manifestReader.js"

export async function transformManifest(config: Config) {
    printPathInfo(config)

    const resolvedPath = path.resolve(config.manifestPath)
    const xml = await fs.readFile(resolvedPath)
    const parser = new xml2js.Parser()
    const manifest: Manifest = await parser.parseStringPromise(xml)

    core.info(`Transforming Outlook web addin:`)
    rewriteAddinInfo(manifest, config)

    const iconUrls = getIconUrls(manifest)
    rewriteUrls(iconUrls, config)

    const appDomains = getAppDomains(manifest)
    rewriteAppDomains(appDomains, config)

    const sourceLocations = getSourceLocations(manifest)
    rewriteUrls(sourceLocations, config)

    const resourceImages = getResourceImages(manifest)
    rewriteUrls(resourceImages, config)

    const resourceUrls = getResourceUrls(manifest)
    rewriteUrls(resourceUrls, config)

    const webappInfo = getWebApplicationInfo(manifest)
    rewriteWebappInfo(webappInfo, config)

    const builder = new xml2js.Builder()
    const transformedXml = builder.buildObject(manifest)
    await fs.writeFile(config.outputPath, transformedXml)

    return manifest
}

function rewriteAddinInfo(manifest: Manifest, config: AddinConfig) {
    core.info(`Transforming addin info`)
    printAddinInfo(manifest)

    manifest.OfficeApp.Id = config.addinAppId
    if (config.addinAppName) {
        manifest.OfficeApp.DisplayName[0].$.DefaultValue = config.addinAppName
    }

    core.info(`Transformed`)
    printAddinInfo(manifest)
}

function rewriteUrls(resourceUrls: ResourceUrl[], config: ServerConfig) {
    for (const resourceUrl of resourceUrls) {
        const fromUrl = resourceUrl.$.DefaultValue
        const toUrl = transformUrl(fromUrl, config)

        resourceUrl.$.DefaultValue = toUrl
    }
}

function rewriteAppDomains(urls: string[], config: ServerConfig) {
    let containsTarget = false

    let i = urls.length - 1
    while (i >= 0) {
        const url = new URL(urls[i])

        if (url.host.startsWith("localhost")) {
            core.info(`    removing: ${urls[i]}`)
            urls.splice(i, 1)
        } else if (
            url.host === config.serverHost &&
            url.port === config.serverPort
        ) {
            containsTarget = true
        }

        i--
    }

    if (!containsTarget) {
        const serverAppDomain = getServerAppDomain(config)
        core.info(`    adding: ${serverAppDomain}`)
        urls.push(serverAppDomain)
    }
}

function rewriteWebappInfo(
    webappInfo: WebApplicationInfo,
    config: AzureConfig
) {
    core.info(`Transforming web application info`)
    printAzureInfo(webappInfo)

    webappInfo.Id = config.azureAppId
    webappInfo.Resource = config.azureAppUri

    core.info(`Transformed`)
    printAzureInfo(webappInfo)
}

function transformUrl(fromUrl: string, config: ServerConfig) {
    const url = new URL(fromUrl)
    url.host = config.serverHost
    url.port = config.serverPort
    url.pathname = `${config.serverPath}${url.pathname}`

    const toUrl = url.href

    printUrlTransform(fromUrl, toUrl)
    return toUrl
}

function getServerAppDomain(config: ServerConfig) {
    const domain = `https://${config.serverHost}`
    const url = new URL(domain)
    url.port = config.serverPort

    return url.href.slice(0, -1)
}
