// Copyright 2022 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {CoconutDemoState, set_panic_hook} from "@nymproject/coconut-wasm-wrapper"

// hehe, javascript globals
let appState = null

function disableById(id) {
    const element = document.getElementById(id)
    element.setAttribute('disabled', 'true')
}

function showById(id) {
    const element = document.getElementById(id)
    element.removeAttribute('hidden')
}

function setError(msg) {
    const errorParagraph = document.getElementById('error-msg');
    errorParagraph.innerText = msg
}

function resetError() {
    setError("")
}

function setCredentialValidity(isValid) {
    const wrapperDiv = document.getElementById('credential-validity')
    let validityText = ""
    let validityColour = ""
    if (isValid) {
        validityText = "Your credential is valid!"
        validityColour = "green"
    } else {
        validityText = "Your credential is invalid!"
        validityColour = "red"
    }
    const bold = document.createElement('b')
    bold.innerText = validityText
    bold.setAttribute('style', `color: ${validityColour}`)

    wrapperDiv.replaceChildren(bold)
}

function verifyCredential(attributes, verificationKey, credential) {
    console.log("verifying ", credential)
    console.log("on the following attributes: ", attributes)
    console.log("with the following aggregated verification key used in proofs: ", verificationKey)
    const validity = appState.verify_credential(attributes, credential, verificationKey)
    setCredentialValidity(validity)
}

function aggregateVerificationKeys() {
    let aggregationResult = appState.aggregate_verification_keys();
    console.log("the verification keys got aggregated to", aggregationResult)

    let usedIndices = aggregationResult.used_indices;
    let vk = aggregationResult.aggregated_verification_key;
    let threshold = appState.threshold

    const aggregationTextDiv = document.getElementById('vk-aggregation-text')
    let formattedSigners = ""
    for (let i = 0; i < usedIndices.length; i++) {
        formattedSigners += `Signer${usedIndices[i]} `
    }
    formattedSigners.trimEnd()
    const text = document.createTextNode(`Pseudorandomly chose verification keys from the following signers: ${formattedSigners} for aggregation. We had to choose any ${threshold} (threshold) number of them.`)
    aggregationTextDiv.replaceChildren(text)

    const aggregatedVKDiv = document.getElementById('aggregated-vk')
    const fieldset = document.createElement('fieldset')
    const legend = document.createElement('legend')
    legend.innerText = "Aggregated Verification Key"

    const span = document.createElement('span')
    span.setAttribute('id', 'agg-vk-span')
    span.innerText = vk.substring(0, 64) + "....."

    fieldset.appendChild(legend)
    fieldset.appendChild(span)
    fieldset.appendChild(document.createElement('br'))
    aggregatedVKDiv.replaceChildren(fieldset)

    return vk
}

function aggregateIssuedPartialSignatures() {
    let aggregationResult = appState.aggregate_signatures();
    console.log("the signatures got aggregated to", aggregationResult)

    let usedIndices = aggregationResult.used_indices;
    let signature = aggregationResult.aggregated_signature;
    let threshold = appState.threshold

    const aggregationTextDiv = document.getElementById('sig-aggregation-text')
    let formattedSigners = ""
    for (let i = 0; i < usedIndices.length; i++) {
        formattedSigners += `Signer${usedIndices[i]} `
    }
    formattedSigners.trimEnd()
    const text = document.createTextNode(`Pseudorandomly chose signatures from the following signers: ${formattedSigners} for aggregation. We had to choose any ${threshold} (threshold) number of them.`)
    aggregationTextDiv.appendChild(text)

    const aggregatedSignatureDiv = document.getElementById('aggregated-signature')
    const fieldset = document.createElement('fieldset')
    const legend = document.createElement('legend')
    legend.innerText = "Coconut Credential"

    const span = document.createElement('span')
    span.setAttribute('id', 'credential-span')
    span.innerText = signature

    const randomiseButton = document.createElement('button')
    randomiseButton.setAttribute('id', 'randomise-credential-btn')
    randomiseButton.innerText = 'Randomise the credential'
    randomiseButton.onclick = () => {
        span.innerText = appState.randomise_credential()
    }

    fieldset.appendChild(legend)
    fieldset.appendChild(span)
    fieldset.appendChild(document.createElement('br'))
    fieldset.appendChild(randomiseButton)
    aggregatedSignatureDiv.appendChild(fieldset)

    aggregationTextDiv.removeAttribute('hidden')
    aggregatedSignatureDiv.removeAttribute('hidden')

    const verificationButton = document.getElementById('start-verification-btn')
    verificationButton.removeAttribute('hidden')
    verificationButton.onclick = () => {
        showById('verification-steps-div')
        createAttributesInput('attributes-verification', onVerificationAttributesSubmit)
    }
}

function showPartialSignatures(signatures) {
    const signaturesTable = document.getElementById('partial-signatures')

    const tableBody = document.createElement('tbody')

    for (let i = 1; i <= signatures.length; i++) {
        const blindedSignature = signatures[i - 1].blinded;
        const unblindedSignature = signatures[i - 1].unblinded;
        console.log(blindedSignature)
        console.log(unblindedSignature)

        const row = document.createElement('tr')
        const data1 = document.createElement('td')
        data1.innerText = `Signer${i}`

        const data2 = document.createElement('td')
        const fullBlindedSigDiv = document.createElement('div')
        fullBlindedSigDiv.setAttribute('title', blindedSignature)

        // show only part of the signature due to its (relatively) massive size
        fullBlindedSigDiv.innerText = "....." + blindedSignature.substring(64, 96) + "....."
        data2.appendChild(fullBlindedSigDiv)

        const data3 = document.createElement('td')
        const fullUnblindedSigDiv = document.createElement('div')
        fullUnblindedSigDiv.setAttribute('title', unblindedSignature)

        // show only part of the signature due to its (relatively) massive size
        fullUnblindedSigDiv.innerText = "....." + unblindedSignature.substring(64, 96) + "....."
        data3.appendChild(fullUnblindedSigDiv)

        row.appendChild(data1)
        row.appendChild(data2)
        row.appendChild(data3)
        tableBody.appendChild(row)
    }

    signaturesTable.appendChild(tableBody)
    signaturesTable.removeAttribute('hidden')

    aggregateIssuedPartialSignatures()
}

function createAuthorities(numAuthorities) {
    console.log("signing authorities creation")

    const verificationKeys = appState.signing_authorities_public_keys()
    console.log("obtained the following verification keys ", verificationKeys)

    const authoritiesTable = document.getElementById('authorities')
    const tableBody = document.createElement('tbody')

    for (let i = 1; i <= numAuthorities; i++) {
        const row = document.createElement('tr')
        const data1 = document.createElement('td')
        data1.innerText = `Signer${i}`

        const data2 = document.createElement('td')
        const vkDiv = document.createElement('div')
        vkDiv.setAttribute('title', verificationKeys[i - 1])

        // show only part of the key due to its massive size
        vkDiv.innerText = verificationKeys[i - 1].substring(0, 64) + "....."
        data2.appendChild(vkDiv)

        row.appendChild(data1)
        row.appendChild(data2)
        tableBody.appendChild(row)
    }

    authoritiesTable.appendChild(tableBody)
    authoritiesTable.removeAttribute('hidden')
}

function collectSubmittedAttributes(wrapperDivId, disableForm) {
    resetError()
    console.log("attributes submission")

    const numAttributes = document.getElementById('num-attributes').value
    let attributes = []

    // ensure there's at least a single private attribute
    let hasPrivate = false
    for (let i = 1; i <= numAttributes; i++) {
        const isPrivate = document.getElementById(`${wrapperDivId}-attr${i}-private`).checked;
        if (isPrivate) {
            hasPrivate = true
            break
        }
    }

    if (!hasPrivate) {
        setError("You need to provide at least a single private attribute to sign!")
        return
    }

    for (let i = 1; i <= numAttributes; i++) {
        const valueElement = document.getElementById(`${wrapperDivId}-attr${i}-val`)
        const isPrivateElement = document.getElementById(`${wrapperDivId}-attr${i}-private`)

        if (disableForm) {
            valueElement.setAttribute('disabled', 'true')
            isPrivateElement.setAttribute('disabled', 'true')
        }

        const value = valueElement.value
        const isPrivate = isPrivateElement.checked

        const attribute = {
            value: value,
            is_private: isPrivate
        }
        attributes.push(attribute)
    }

    if(disableForm){
        disableById(`${wrapperDivId}-confirm-btn`)
    }

    return attributes
}

function onIssuanceAttributeSubmit() {
    console.log("issuance attributes submit")

    appState.raw_attributes = collectSubmittedAttributes('attributes-issuance', true)

    const sigs = appState.blind_sign_attributes()
    showPartialSignatures(sigs)
}

function onVerificationAttributesSubmit() {
    console.log("verification attributes submit")

    const attributes = collectSubmittedAttributes('attributes-verification', false)
    const aggregatedVk = aggregateVerificationKeys()
    const credential = appState.current_credential

    verifyCredential(attributes, aggregatedVk, credential)
}

function createAttributesInput(wrapperDivId, confirmCallback) {
    const numAttributes = document.getElementById('num-attributes').value
    const inputDiv = document.getElementById(wrapperDivId)
    const innerDiv = document.createElement('div')

    for (let i = 1; i <= numAttributes; i++) {
        // hehe, that's so disgusting
        const wrapperDiv = document.createElement('div')
        const fieldset = document.createElement('fieldset')
        const legend = document.createElement('legend')
        legend.innerText = `Attribute ${i}/${numAttributes}`

        const inputValue = document.createElement('input')
        inputValue.setAttribute('type', 'text')
        inputValue.setAttribute('id', `${wrapperDivId}-attr${i}-val`)

        const inputPrivate = document.createElement('input')
        inputPrivate.setAttribute('type', 'checkbox')
        inputPrivate.setAttribute('id', `${wrapperDivId}-attr${i}-private`)

        const checkboxText = document.createTextNode("Private Attribute")

        fieldset.appendChild(legend)
        fieldset.appendChild(inputValue)
        fieldset.appendChild(inputPrivate)
        fieldset.appendChild(checkboxText)

        wrapperDiv.appendChild(fieldset)
        innerDiv.appendChild(wrapperDiv)
    }

    const wrapperPara = document.createElement('p')
    const submitButton = document.createElement('button')
    submitButton.setAttribute('id', `${wrapperDivId}-confirm-btn`)
    submitButton.innerText = 'Confirm'
    submitButton.onclick = confirmCallback

    wrapperPara.appendChild(submitButton)
    innerDiv.appendChild(wrapperPara)
    inputDiv.replaceChildren(innerDiv)
}

function main() {
    // sets up better stack traces in case of in-rust panics
    set_panic_hook();

    const confirmButton = document.getElementById('form-confirm-btn');

    confirmButton.onclick = function () {
        console.log("parameters submission")
        resetError()

        const authoritiesElement = document.getElementById('num-authorities')
        const attributesElement = document.getElementById('num-attributes')
        const thresholdElement = document.getElementById('threshold')

        const authorities = authoritiesElement.value;
        const attributes = attributesElement.value;
        const threshold = thresholdElement.value;

        if (authorities <= 0) {
            setError("You must use at least a single signing authority")
            return
        }

        if (attributes <= 0) {
            setError("You must use at least a single attribute in your credential")
            return
        }

        if (threshold <= 0) {
            setError("Your signing threshold must be greater than 0")
            return
        }

        if (threshold > authorities) {
            setError("Your signing threshold can't be larger than the total number of signing authorities")
            return
        }

        confirmButton.setAttribute('disabled', 'true')
        authoritiesElement.setAttribute('disabled', 'true')
        attributesElement.setAttribute('disabled', 'true')
        thresholdElement.setAttribute('disabled', 'true')

        appState = new CoconutDemoState(attributes, authorities, threshold)

        createAuthorities(authorities)
        showById('issuance-header')
        createAttributesInput('attributes-issuance', onIssuanceAttributeSubmit)
    }
}

// Let's get started!
main();