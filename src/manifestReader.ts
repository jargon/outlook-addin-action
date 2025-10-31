import * as core from "@actions/core"
import { Manifest } from "./manifestTypes.js"

export function getDisplayName(manifest: Manifest) {
    return manifest.OfficeApp.DisplayName[0]
}

export function getResources(manifest: Manifest) {
    const ver11Overrides = getVersion11Overrides(manifest)
    return ver11Overrides.Resources[0]
}

export function getWebApplicationInfo(manifest: Manifest) {
    const ver11Overrides = getVersion11Overrides(manifest)
    return ver11Overrides.WebApplicationInfo[0]
}

export function getIconUrls(manifest: Manifest) {
    const iconUrl = manifest.OfficeApp.IconUrl[0]
    const hiResUrl = manifest.OfficeApp.HighResolutionIconUrl[0]
    const result = [iconUrl, hiResUrl].filter((val) => !!val)
    core.info(`Found ${result.length} icon URLs`)

    return [iconUrl, hiResUrl]
}

export function getAppDomains(manifest: Manifest) {
    const appDomains = manifest.OfficeApp.AppDomains[0]
    core.info(`Found ${appDomains.AppDomain.length} app domains`)

    return appDomains.AppDomain
}

export function getSourceLocations(manifest: Manifest) {
    const sourceLocations = manifest.OfficeApp.FormSettings.flatMap(
        (fs) => fs.Form
    )
        .flatMap((frm) => frm.DesktopSettings)
        .flatMap((ds) => ds.SourceLocation)

    core.info(`Found ${sourceLocations.length} source locations`)
    return sourceLocations
}

export function getResourceImages(manifest: Manifest) {
    const resources = getResources(manifest)
    const resourceImages = resources["bt:Images"][0]["bt:Image"]
    core.info(`Found ${resourceImages.length} image URLs`)

    return resourceImages
}

export function getResourceUrls(manifest: Manifest) {
    const resources = getResources(manifest)
    const resourceUrls = resources["bt:Urls"][0]["bt:Url"]
    core.info(`Found ${resourceUrls.length} resource URLs`)

    return resourceUrls
}

function getVersion11Overrides(manifest: Manifest) {
    const ver10Overrides = manifest.OfficeApp.VersionOverrides[0]
    const ver11Overrides = ver10Overrides.VersionOverrides[0]

    return ver11Overrides
}
