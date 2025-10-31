import * as fs from "node:fs/promises"
import * as path from "node:path"
import { vi, describe, beforeEach, afterEach, test, chai } from "vitest"
import xml2js from "xml2js"
import { Manifest } from "../src/manifestTypes"
import {
    getDisplayName,
    getIconUrls,
    getResources,
    getWebApplicationInfo
} from "../src/manifestReader"

const expect = chai.expect
let manifest: Manifest | undefined = undefined

describe("manifestReader.ts", () => {
    beforeEach(async () => {
        const resolvedPath = path.resolve("./__tests__/test-manifest.xml")
        const xml = await fs.readFile(resolvedPath)
        const parser = new xml2js.Parser()
        manifest = await parser.parseStringPromise(xml)

        // Setup mocks here
    })

    afterEach(() => {
        vi.resetAllMocks()

        manifest = undefined
    })

    describe("getDisplayName", () => {
        test("returns the display name from manifest", () => {
            const actual = getDisplayName(manifest!)
            expect(actual)
                .to.have.property("$")
                .to.have.property("DefaultValue")
                .which.is.equal("Contoso Add-in")
        })
    })

    describe("getResources", () => {
        test("returns the Resources element inside version overrides", () => {
            const actual = getResources(manifest!)
            expect(actual).to.have.property("bt:Images")
            expect(actual).to.have.property("bt:Urls")
        })
    })

    describe("getWebApplicationInfo", () => {
        test("returns the WebApplicationInfo element inside version overrides", () => {
            const actual = getWebApplicationInfo(manifest!)
            expect(actual).to.have.property("Id")
            expect(actual).to.have.property("Resource")
        })
    })

    describe("getIconUrls", () => {
        test("returns the IconUrl and HighResolutionIconUrl elements in an array", () => {
            const actual = getIconUrls(manifest!)
            expect(actual).to.be.an("array")
        })
    })
})
