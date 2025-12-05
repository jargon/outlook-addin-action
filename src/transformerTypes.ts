export type PathConfig = Readonly<{
    manifestPath: string
    outputPath: string
}>

export type ServerConfig = Readonly<{
    serverHost: string
    serverPort: string
    serverPath: string
}>

export type AddinConfig = Readonly<{
    addinAppId: string
}>

export type AzureConfig = Readonly<{
    azureAppId: string
    azureAppUri: string
}>

export type Config = PathConfig & ServerConfig & AddinConfig & AzureConfig
