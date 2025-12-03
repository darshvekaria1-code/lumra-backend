import pdf from "pdf-parse"
import { readFileSync } from "fs"
import { join, extname } from "path"
import mammoth from "mammoth"
import * as XLSX from "xlsx"

/**
 * Extract text from PDF file
 */
export async function extractTextFromPDF(fileBuffer) {
    try {
        const data = await pdf(fileBuffer)
        return data.text.trim()
    } catch (error) {
        throw new Error(`Failed to extract text from PDF: ${error.message}`)
    }
}

/**
 * Extract text from text file
 */
export function extractTextFromTextFile(fileBuffer, encoding = "utf-8") {
    try {
        return fileBuffer.toString(encoding).trim()
    } catch (error) {
        throw new Error(`Failed to extract text from file: ${error.message}`)
    }
}

/**
 * Extract text from Word document (.docx)
 */
export async function extractTextFromWord(fileBuffer) {
    try {
        const result = await mammoth.extractRawText({ buffer: fileBuffer })
        return result.value.trim()
    } catch (error) {
        throw new Error(`Failed to extract text from Word document: ${error.message}`)
    }
}

/**
 * Extract text from Excel file (.xlsx, .xls)
 */
export function extractTextFromExcel(fileBuffer) {
    try {
        const workbook = XLSX.read(fileBuffer, { type: 'buffer', cellDates: true, cellNF: false, cellText: false })
        const textParts = []
        
        // Extract text from all sheets with better formatting
        workbook.SheetNames.forEach((sheetName) => {
            const worksheet = workbook.Sheets[sheetName]
            
            // Convert to JSON first to preserve structure
            const jsonData = XLSX.utils.sheet_to_json(worksheet, { 
                header: 1, // Use array format to preserve row/column structure
                defval: '', // Default value for empty cells
                raw: false // Convert numbers to strings for better readability
            })
            
            if (jsonData && jsonData.length > 0) {
                // Format as table with headers
                let sheetText = `=== SHEET: ${sheetName} ===\n\n`
                
            // Format as structured table
            if (jsonData.length > 0) {
                // Check if first row contains headers (non-numeric, descriptive text)
                const firstRow = jsonData[0] || []
                const hasHeaders = firstRow.some(cell => {
                    const cellStr = String(cell).trim()
                    return cellStr && !/^\d+$/.test(cellStr) && cellStr.length > 0
                })
                
                if (hasHeaders && jsonData.length > 1) {
                    // First row is headers
                    const headers = firstRow.map(cell => {
                        const val = cell !== null && cell !== undefined ? String(cell).trim() : ''
                        return val || ''
                    }).filter(h => h !== '')
                    
                    // Count non-empty headers
                    const nonEmptyHeaders = headers.filter(h => h && h !== '').length
                    const dataRowCount = jsonData.length - 1
                    
                    sheetText += `EXCEL SPREADSHEET DATA:\n`
                    sheetText += `Sheet Name: "${sheetName}"\n`
                    sheetText += `Total Columns: ${nonEmptyHeaders}\n`
                    sheetText += `Total Data Rows: ${dataRowCount}\n\n`
                    sheetText += `COLUMN HEADERS:\n${headers.filter(h => h).join(' | ')}\n\n`
                    sheetText += `DATA ROWS:\n`
                    
                    // Process data rows with header mapping - format clearly
                    for (let i = 1; i < jsonData.length; i++) {
                        const row = jsonData[i] || []
                        const rowData = []
                        
                        headers.forEach((header, colIdx) => {
                            const cellValue = row[colIdx]
                            if (cellValue !== null && cellValue !== undefined) {
                                const valueStr = String(cellValue).trim()
                                if (valueStr !== '') {
                                    rowData.push(`${header}: "${valueStr}"`)
                                }
                            }
                        })
                        
                        if (rowData.length > 0) {
                            sheetText += `Entry ${i}:\n  ${rowData.join('\n  ')}\n\n`
                        }
                    }
                } else {
                    // No clear headers - show all data in a structured way
                    sheetText += `EXCEL SPREADSHEET DATA:\n`
                    sheetText += `Sheet Name: "${sheetName}"\n`
                    sheetText += `Total Rows: ${jsonData.length}\n\n`
                    sheetText += `DATA:\n`
                    
                    jsonData.forEach((row, rowIndex) => {
                        if (row && row.length > 0) {
                            const rowValues = row
                                .map((cell, colIdx) => {
                                    if (cell !== null && cell !== undefined) {
                                        const valueStr = String(cell).trim()
                                        if (valueStr !== '') {
                                            return `Column_${colIdx + 1}: "${valueStr}"`
                                        }
                                    }
                                    return null
                                })
                                .filter(item => item !== null)
                            
                            if (rowValues.length > 0) {
                                sheetText += `Row ${rowIndex + 1}:\n  ${rowValues.join('\n  ')}\n\n`
                            }
                        }
                    })
                }
            }
                
                if (sheetText.trim().length > `=== SHEET: ${sheetName} ===\n\n`.length) {
                    textParts.push(sheetText.trim())
                }
            }
        })
        
        if (textParts.length === 0) {
            // Fallback to CSV if JSON conversion fails
            workbook.SheetNames.forEach((sheetName) => {
                const worksheet = workbook.Sheets[sheetName]
                const sheetData = XLSX.utils.sheet_to_csv(worksheet)
                if (sheetData.trim()) {
                    textParts.push(`=== SHEET: ${sheetName} ===\n\n${sheetData}`)
                }
            })
        }
        
        const extractedText = textParts.join('\n\n').trim()
        if (!extractedText) {
            throw new Error("No data found in Excel file")
        }
        
        // Log extraction summary for debugging
        console.log(`[Excel Extraction] ✅ Extracted ${textParts.length} sheet(s), total length: ${extractedText.length} chars`)
        console.log(`[Excel Extraction] Preview: ${extractedText.substring(0, 500)}...`)
        
        return extractedText
    } catch (error) {
        throw new Error(`Failed to extract text from Excel file: ${error.message}`)
    }
}

/**
 * Extract text from PowerPoint file (.pptx)
 * Note: .ppt (old format) has limited support
 */
export async function extractTextFromPowerPoint(fileBuffer) {
    try {
        // .pptx files are ZIP archives containing XML files
        // Use adm-zip to extract and parse XML
        const AdmZip = (await import("adm-zip")).default
        const zip = new AdmZip(fileBuffer)
        const zipEntries = zip.getEntries()
        const textParts = []
        let slideIndex = 0
        
        // Sort entries to process slides in order
        const slideEntries = zipEntries
            .filter(entry => entry.entryName.includes('ppt/slides/slide') && entry.entryName.endsWith('.xml'))
            .sort((a, b) => {
                // Extract slide numbers for sorting
                const aNum = parseInt(a.entryName.match(/slide(\d+)/)?.[1] || '0')
                const bNum = parseInt(b.entryName.match(/slide(\d+)/)?.[1] || '0')
                return aNum - bNum
            })
        
        for (const entry of slideEntries) {
            try {
                const content = zip.readAsText(entry)
                slideIndex++
                const slideTexts = []
                
                // Extract text from XML - PowerPoint uses <a:t> tags for text
                const textMatches = content.match(/<a:t[^>]*>([^<]+)<\/a:t>/g)
                if (textMatches && textMatches.length > 0) {
                    textMatches.forEach(match => {
                        const text = match.replace(/<[^>]+>/g, '').trim()
                        if (text) {
                            slideTexts.push(text)
                        }
                    })
                }
                
                // Also try alternative XML structure
                if (slideTexts.length === 0) {
                    const altMatches = content.match(/<t[^>]*>([^<]+)<\/t>/g)
                    if (altMatches) {
                        altMatches.forEach(match => {
                            const text = match.replace(/<[^>]+>/g, '').trim()
                            if (text) {
                                slideTexts.push(text)
                            }
                        })
                    }
                }
                
                if (slideTexts.length > 0) {
                    textParts.push(`Slide ${slideIndex}:\n${slideTexts.join('\n')}`)
                }
            } catch (entryError) {
                console.log(`[Document Processor] Error processing slide ${slideIndex + 1}: ${entryError.message}`)
            }
        }
        
        if (textParts.length > 0) {
            return textParts.join('\n\n').trim()
        }
        
        return "No text content found in presentation. PowerPoint file may be image-based, encrypted, or in an unsupported format (.ppt files have limited support)."
    } catch (error) {
        throw new Error(`Failed to extract text from PowerPoint file: ${error.message}`)
    }
}

/**
 * Chunk text into smaller pieces for better retrieval
 * @param {string} text - The text to chunk
 * @param {number} chunkSize - Maximum characters per chunk (default: 1000)
 * @param {number} overlap - Characters to overlap between chunks (default: 200)
 * @returns {Array<{text: string, index: number}>} Array of text chunks
 */
export function chunkText(text, chunkSize = 1000, overlap = 200) {
    if (!text || text.length === 0) {
        return []
    }

    const chunks = []
    let startIndex = 0
    let chunkIndex = 0

    while (startIndex < text.length) {
        let endIndex = startIndex + chunkSize

        // If not the last chunk, try to break at sentence boundary
        if (endIndex < text.length) {
            // Look for sentence endings within the last 200 chars
            const searchStart = Math.max(startIndex, endIndex - 200)
            const lastSentence = text.lastIndexOf(". ", endIndex)
            const lastNewline = text.lastIndexOf("\n", endIndex)

            // Prefer sentence boundary, then newline, then just cut
            if (lastSentence > searchStart) {
                endIndex = lastSentence + 1
            } else if (lastNewline > searchStart) {
                endIndex = lastNewline + 1
            }
        } else {
            endIndex = text.length
        }

        const chunk = text.substring(startIndex, endIndex).trim()

        if (chunk.length > 0) {
            chunks.push({
                text: chunk,
                index: chunkIndex,
                startChar: startIndex,
                endChar: endIndex,
            })
            chunkIndex++
        }

        // Move start index with overlap
        startIndex = endIndex - overlap
        if (startIndex < 0) startIndex = 0
    }

    return chunks
}

/**
 * Process uploaded file and extract text
 * @param {Buffer} fileBuffer - File buffer
 * @param {string} mimeType - MIME type of the file
 * @param {string} filename - Original filename
 * @returns {Promise<string>} Extracted text
 */
export async function processDocument(fileBuffer, mimeType, filename) {
    const extension = extname(filename).toLowerCase()

    try {
        // Handle PDF files
        if (mimeType === "application/pdf" || extension === ".pdf") {
            return await extractTextFromPDF(fileBuffer)
        }

        // Handle Word documents (.docx, .doc)
        if (
            mimeType === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
            mimeType === "application/msword" ||
            extension === ".docx" ||
            extension === ".doc"
        ) {
            return await extractTextFromWord(fileBuffer)
        }

        // Handle Excel files (.xlsx, .xls)
        if (
            mimeType === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" ||
            mimeType === "application/vnd.ms-excel" ||
            extension === ".xlsx" ||
            extension === ".xls"
        ) {
            return extractTextFromExcel(fileBuffer)
        }

        // Handle PowerPoint files (.pptx, .ppt)
        if (
            mimeType === "application/vnd.openxmlformats-officedocument.presentationml.presentation" ||
            mimeType === "application/vnd.ms-powerpoint" ||
            extension === ".pptx" ||
            extension === ".ppt"
        ) {
            return await extractTextFromPowerPoint(fileBuffer)
        }

        // Handle text files
        if (
            mimeType.startsWith("text/") ||
            extension === ".txt" ||
            extension === ".md" ||
            extension === ".markdown" ||
            extension === ".rtf"
        ) {
            return extractTextFromTextFile(fileBuffer)
        }

        // Handle other text-based formats
        if (
            extension === ".json" ||
            extension === ".csv" ||
            extension === ".xml" ||
            extension === ".html" ||
            extension === ".htm" ||
            extension === ".yaml" ||
            extension === ".yml"
        ) {
            return extractTextFromTextFile(fileBuffer)
        }

        throw new Error(
            `Unsupported file type: ${mimeType || extension}. Supported types: PDF, DOCX, DOC, XLSX, XLS, PPTX, PPT, TXT, MD, RTF, JSON, CSV, XML, HTML, YAML`
        )
    } catch (error) {
        throw new Error(`Document processing failed: ${error.message}`)
    }
}

/**
 * Get file metadata
 */
export function getFileMetadata(filename, fileSize) {
    return {
        filename,
        size: fileSize,
        uploadedAt: new Date().toISOString(),
    }
}


