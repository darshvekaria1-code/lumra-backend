import { chunkText, processDocument } from "./documentProcessor.js"
import {
    initializeVectorDB,
    storeDocumentChunks,
    searchSimilarChunks,
    deleteDocument,
    isVectorDBAvailable,
} from "./vectorDB.js"

let openaiClient = null

/**
 * Initialize RAG system with OpenAI client
 * @param {OpenAI} client - OpenAI client instance
 */
export function initializeRAG(client) {
    openaiClient = client
    return initializeVectorDB()
}

/**
 * Create embedding for text using OpenAI
 * @param {string} text - Text to create embedding for
 * @returns {Promise<Array<number>>} Embedding vector
 */
export async function createEmbedding(text) {
    if (!openaiClient) {
        throw new Error("OpenAI client not initialized")
    }

    try {
        const response = await openaiClient.embeddings.create({
            model: process.env.EMBEDDING_MODEL || "text-embedding-3-small",
            input: text.substring(0, 8000), // Limit to 8000 chars (API limit)
        })

        return response.data[0].embedding
    } catch (error) {
        console.error(`[RAG] ❌ Failed to create embedding: ${error.message}`)
        throw new Error(`Embedding creation failed: ${error.message}`)
    }
}

/**
 * Create embeddings for multiple texts
 * @param {Array<string>} texts - Array of texts
 * @returns {Promise<Array<Array<number>>>} Array of embedding vectors
 */
export async function createEmbeddings(texts) {
    if (!openaiClient) {
        throw new Error("OpenAI client not initialized")
    }

    try {
        // Process in batches to avoid rate limits
        const batchSize = 10
        const embeddings = []

        for (let i = 0; i < texts.length; i += batchSize) {
            const batch = texts.slice(i, i + batchSize)
            const batchTexts = batch.map((text) => text.substring(0, 8000))

            const response = await openaiClient.embeddings.create({
                model: process.env.EMBEDDING_MODEL || "text-embedding-3-small",
                input: batchTexts,
            })

            embeddings.push(...response.data.map((item) => item.embedding))
        }

        return embeddings
    } catch (error) {
        console.error(`[RAG] ❌ Failed to create embeddings: ${error.message}`)
        throw new Error(`Embeddings creation failed: ${error.message}`)
    }
}

/**
 * Process and store document in vector database
 * @param {Buffer} fileBuffer - File buffer
 * @param {string} mimeType - MIME type
 * @param {string} filename - Original filename
 * @param {string} documentId - Unique document ID
 * @param {string} userId - User ID
 * @returns {Promise<{success: boolean, chunks: number, text: string}>}
 */
export async function processAndStoreDocument(
    fileBuffer,
    mimeType,
    filename,
    documentId,
    userId
) {
    try {
        // 1. Extract text from document
        const text = await processDocument(fileBuffer, mimeType, filename)

        if (!text || text.trim().length === 0) {
            throw new Error("No text extracted from document")
        }

        // 2. Chunk the text
        // Use larger chunks for better context (especially for Excel/structured data)
        const chunkSize = parseInt(process.env.CHUNK_SIZE || "2000", 10) // Increased from 1000 to 2000
        const overlap = parseInt(process.env.CHUNK_OVERLAP || "300", 10) // Increased from 200 to 300
        const chunks = chunkText(text, chunkSize, overlap)

        if (chunks.length === 0) {
            throw new Error("No chunks created from document")
        }

        console.log(
            `[RAG] 📄 Processed document: ${filename} - ${chunks.length} chunks created`
        )
        console.log(`[RAG] 📊 Document preview (first 500 chars): ${text.substring(0, 500)}...`)
        if (chunks.length > 0) {
            console.log(`[RAG] 📋 First chunk preview: ${chunks[0].text.substring(0, 200)}...`)
        }

        // 3. Create embeddings for all chunks
        const chunkTexts = chunks.map((chunk) => chunk.text)
        const embeddings = await createEmbeddings(chunkTexts)

        // 4. Store in vector database
        const documentMetadata = {
            filename,
            mimeType,
            uploadedAt: new Date().toISOString(),
            textLength: text.length,
            chunkCount: chunks.length,
        }

        await storeDocumentChunks(
            chunks,
            documentId,
            userId,
            documentMetadata,
            embeddings
        )

        return {
            success: true,
            chunks: chunks.length,
            text: text.substring(0, 500), // Return first 500 chars as preview
            totalLength: text.length,
        }
    } catch (error) {
        console.error(`[RAG] ❌ Document processing failed: ${error.message}`)
        throw error
    }
}

/**
 * Retrieve relevant document chunks for a query
 * @param {string} query - User's question/query
 * @param {string} userId - User ID
 * @param {number} topK - Number of results to return (default: 5)
 * @returns {Promise<Array<{text: string, metadata: object, relevance: number}>>}
 */
export async function retrieveRelevantDocuments(query, userId, topK = 5) {
    if (!isVectorDBAvailable()) {
        console.log("[RAG] ⚠️  Vector DB not available, skipping RAG retrieval")
        return []
    }

    if (!openaiClient) {
        console.log("[RAG] ⚠️  OpenAI client not available, skipping RAG retrieval")
        return []
    }

    try {
        console.log(`[RAG] 🔍 Searching for relevant documents for query: "${query.substring(0, 100)}..."`)
        
        // 1. Create embedding for the query
        const queryEmbedding = await createEmbedding(query)
        console.log(`[RAG] ✅ Created query embedding (${queryEmbedding.length} dimensions)`)

        // 2. Search for similar chunks
        const results = await searchSimilarChunks(queryEmbedding, userId, topK)
        console.log(`[RAG] 📊 Found ${results.length} potential matches`)

        // 3. Filter by relevance threshold (optional)
        // Use very low threshold to ensure we get results if documents exist
        const relevanceThreshold = parseFloat(
            process.env.RAG_RELEVANCE_THRESHOLD || "0.1" // Very low threshold (0.1) to ensure we get results
        )
        const filteredResults = results.filter(
            (result) => result.relevance >= relevanceThreshold
        )
        
        // If we have results but they're all below threshold, still return them (user has documents)
        const finalResults = filteredResults.length > 0 ? filteredResults : results.slice(0, topK)

        console.log(
            `[RAG] ✅ Found ${finalResults.length} relevant chunks (threshold: ${relevanceThreshold})`
        )

        if (finalResults.length > 0) {
            finalResults.forEach((result, index) => {
                console.log(`[RAG]   ${index + 1}. ${result.metadata.filename || "Document"} (relevance: ${(result.relevance * 100).toFixed(1)}%)`)
            })
        }

        return finalResults
    } catch (error) {
        console.error(`[RAG] ❌ Retrieval failed: ${error.message}`)
        console.error(`[RAG] ❌ Error stack: ${error.stack}`)
        return []
    }
}

/**
 * Format retrieved documents for AI context
 * @param {Array} retrievedDocs - Retrieved document chunks
 * @returns {string} Formatted context string
 */
export function formatRetrievedContext(retrievedDocs) {
    if (!retrievedDocs || retrievedDocs.length === 0) {
        return ""
    }

    const contextParts = retrievedDocs.map((doc, index) => {
        const source = doc.metadata.filename || "Document"
        const relevance = (doc.relevance * 100).toFixed(0)
        return `[Source ${index + 1}: ${source} (Relevance: ${relevance}%)]\n${doc.text}`
    })

    return `\n\n=== ⚠️ CRITICAL: DOCUMENT CONTENT - USE THIS INFORMATION ONLY ===\n\nThe user has uploaded documents. Below is the ACTUAL CONTENT from those documents.\n\nYOU MUST:\n1. READ and ANALYZE the document content below\n2. USE ONLY the information from these documents to answer the user's question\n3. DO NOT use general knowledge or training data - ONLY use what's in the documents below\n4. If information is NOT in the documents, explicitly say "This information is not in the uploaded document(s)"\n5. DO NOT make up or guess information - if it's not in the documents, say so\n6. Cite sources when referencing information (e.g., "According to [filename]..." or "As mentioned in Source 1...")\n\nFORBIDDEN:\n- DO NOT say "I can't open files" or "I can't read files" - you HAVE the file content below\n- DO NOT use general knowledge about topics - ONLY use document content\n- DO NOT guess or infer information not explicitly in the documents\n- DO NOT provide generic information - the user wants specific information from THEIR documents\n\n=== DOCUMENT CONTENT (${retrievedDocs.length} sources found) ===\n\n${contextParts.join("\n\n---\n\n")}\n\n=== END OF DOCUMENT CONTENT ===\n\nREMEMBER: Answer the user's question using ONLY the information from the documents above. If the information is not in the documents, explicitly state that.`
}

/**
 * Delete a document from the RAG system
 * @param {string} documentId - Document ID
 * @returns {Promise<boolean>}
 */
export async function removeDocument(documentId) {
    try {
        return await deleteDocument(documentId)
    } catch (error) {
        console.error(`[RAG] ❌ Failed to remove document: ${error.message}`)
        return false
    }
}

/**
 * Check if RAG is available
 */
export function isRAGAvailable() {
    return isVectorDBAvailable() && openaiClient !== null
}

