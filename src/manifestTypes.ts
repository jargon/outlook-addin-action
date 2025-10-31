type DefaultValueHolder = {
    $: {
        DefaultValue: string
    }
}

export type AppName = DefaultValueHolder
export type ResourceUrl = DefaultValueHolder

type AppDomains = Readonly<
    {
        AppDomain: string[]
    }[]
>

type FormSettings = Readonly<{
    Form: {
        DesktopSettings: {
            SourceLocation: ResourceUrl[]
        }[]
    }[]
}>

type Resources = Readonly<
    {
        "bt:Images": {
            "bt:Image": ResourceUrl[]
        }[]
        "bt:Urls": {
            "bt:Url": ResourceUrl[]
        }[]
    }[]
>

export type WebApplicationInfo = {
    Id: string
    Resource: string
}

type OfficeApp = {
    Id: string
    DisplayName: AppName[]
    IconUrl: ResourceUrl[]
    HighResolutionIconUrl: ResourceUrl[]
    AppDomains: AppDomains
    FormSettings: FormSettings[]
    VersionOverrides: {
        $: {
            "xsi:type": string
        }
        VersionOverrides: {
            $: {
                "xsi:type": string
            }
            Resources: Resources
            WebApplicationInfo: WebApplicationInfo[]
        }[]
    }[]
}

export type Manifest = {
    OfficeApp: OfficeApp
}
