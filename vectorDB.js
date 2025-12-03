import { ChromaClient } from "chromadb"
import { join } from "path"
import { existsSync, mkdirSync } from "fs"

// Initialize ChromaDB client
// For local development, ChromaDB runs in-memory or can use persistent storage
let chromaClient = null
let documentsCollection = null

/**
 * Initialize ChromaDB client and collection
 */
export async function initializeVectorDB() {
    try {
        // ChromaDB can run in-memory or with persistent storage
        // For production, you might want to run a ChromaDB server
        // For now, we'll use in-memory mode (data persists during server runtime)
        const chromaPath = process.env.CHROMA_PATH || join(process.cwd(), "chroma_db")
        
        console.log(`[Vector DB] 🔄 Initializing ChromaDB at: ${chromaPath}`)
        console.log(`[Vector DB] 🔍 Current working directory: ${process.cwd()}`)
        console.log(`[Vector DB] 🔍 ChromaDB path: ${chromaPath}`)
        
        // Create directory if it doesn't exist
        if (!existsSync(chromaPath)) {
            console.log(`[Vector DB] 📁 Creating ChromaDB directory: ${chromaPath}`)
            mkdirSync(chromaPath, { recursive: true })
            console.log(`[Vector DB] ✅ Created ChromaDB directory: ${chromaPath}`)
        } else {
            console.log(`[Vector DB] ✅ ChromaDB directory already exists: ${chromaPath}`)
        }

        console.log(`[Vector DB] 🔄 Creating ChromaClient...`)
        chromaClient = new ChromaClient({
            path: chromaPath,
        })
        console.log(`[Vector DB] ✅ ChromaClient created successfully`)

        // Create or get collection for documents
        // Collection name includes user ID for isolation
        const collectionName = "lumra_documents"

        try {
            // Try to get existing collection first
            try {
                documentsCollection = await chromaClient.getCollection({
                    name: collectionName,
                })
                console.log(`[Vector DB] ✅ Retrieved existing ChromaDB collection: ${collectionName}`)
            } catch (getError) {
                // Collection doesn't exist, create it
                console.log(`[Vector DB] 🔄 Creating new collection: ${collectionName}`)
                documentsCollection = await chromaClient.createCollection({
                    name: collectionName,
                    metadata: { description: "Lumra AI document embeddings" },
                })
                console.log(`[Vector DB] ✅ Created ChromaDB collection: ${collectionName}`)
            }
        } catch (error) {
            console.error(`[Vector DB] ❌ Failed to create/get collection: ${error.message}`)
            console.error(`[Vector DB] ❌ Error details: ${error.stack}`)
            throw error // Re-throw to be caught by outer try-catch
        }

        return true
    } catch (error) {
        console.error(`[Vector DB] ❌ Initialization failed: ${error.message}`)
        console.error(`[Vector DB] ❌ Error stack: ${error.stack}`)
        // If ChromaDB fails, we'll continue without it (graceful degradation)
        // But log the error clearly
        console.error(`[Vector DB] ⚠️  RAG will not be available until ChromaDB is fixed`)
        return false
    }
}

/**
 * Get the documents collection
 */
export function getCollection() {
    return documentsCollection
}

/**
 * Check if vector DB is available
 */
export function isVectorDBAvailable() {
    return documentsCollection !== null && chromaClient !== null
}

/**
 * Store document chunks in vector database
 * @param {Array<{text: string, index: number, metadata?: object}>} chunks - Document chunks
 * @param {string} documentId - Unique document ID
 * @param {string} userId - User ID
 * @param {object} documentMetadata - Additional metadata (filename, source, etc.)
 * @param {Array<Array<number>>} embeddings - Pre-computed embeddings for chunks
 */
export async function storeDocumentChunks(
    chunks,
    documentId,
    userId,
    documentMetadata = {},
    embeddings
) {
    if (!isVectorDBAvailable()) {
        throw new Error("Vector database is not available")
    }

    try {
        const ids = chunks.map((_, index) => `${documentId}_chunk_${index}`)
        const texts = chunks.map((chunk) => chunk.text)
        const metadatas = chunks.map((chunk, index) => ({
            documentId,
            userId,
            chunkIndex: chunk.index || index,
            ...documentMetadata,
            ...chunk.metadata,
        }))

        await documentsCollection.add({
            ids,
            embeddings,
            documents: texts,
            metadatas,
        })

        console.log(
            `[Vector DB] ✅ Stored ${chunks.length} chunks for document ${documentId}`
        )
        return true
    } catch (error) {
        console.error(`[Vector DB] ❌ Failed to store chunks: ${error.message}`)
        throw error
    }
}

/**
 * Search for similar document chunks
 * @param {Array<number>} queryEmbedding - Embedding vector of the query
 * @param {string} userId - User ID to filter results
 * @param {number} topK - Number of results to return (default: 5)
 * @returns {Promise<Array<{text: string, metadata: object, distance: number}>>}
 */
export async function searchSimilarChunks(queryEmbedding, userId, topK = 5) {
    if (!isVectorDBAvailable()) {
        console.log(`[Vector DB] ⚠️  Vector DB not available for search`)
        return []
    }

    try {
        console.log(`[Vector DB] 🔍 Searching for chunks (userId: ${userId}, topK: ${topK})`)
        
        // Try to query with user filter first
        let results
        try {
            results = await documentsCollection.query({
                queryEmbeddings: [queryEmbedding],
                nResults: topK * 2, // Get more results to filter
                where: { userId }, // Filter by user ID for privacy
            })
        } catch (filterError) {
            // If filtered query fails, try without filter (fallback)
            console.log(`[Vector DB] ⚠️  Filtered query failed, trying without filter: ${filterError.message}`)
            results = await documentsCollection.query({
                queryEmbeddings: [queryEmbedding],
                nResults: topK * 2,
            })
            // Then filter results manually by userId
            if (results.documents && results.documents[0]) {
                const filteredIndices = []
                results.metadatas[0].forEach((meta, index) => {
                    if (meta.userId === userId) {
                        filteredIndices.push(index)
                    }
                })
                // Rebuild results with only matching indices
                results.documents[0] = filteredIndices.map(i => results.documents[0][i])
                results.metadatas[0] = filteredIndices.map(i => results.metadatas[0][i])
                if (results.distances && results.distances[0]) {
                    results.distances[0] = filteredIndices.map(i => results.distances[0][i])
                }
            }
        }

        if (!results.documents || results.documents.length === 0 || !results.documents[0] || results.documents[0].length === 0) {
            console.log(`[Vector DB] ℹ️  No documents found in vector DB`)
            return []
        }

        console.log(`[Vector DB] 📊 Found ${results.documents[0].length} chunks from vector DB`)

        // Format results
        const formattedResults = results.documents[0].map((text, index) => {
            const metadata = results.metadatas[0][index] || {}
            const distance = results.distances?.[0]?.[index] || 0
            return {
                text,
                metadata,
                distance,
                relevance: 1 - distance, // Convert distance to relevance score
            }
        })

        // Sort by relevance (highest first)
        formattedResults.sort((a, b) => b.relevance - a.relevance)

        // Return top K results
        const topResults = formattedResults.slice(0, topK)
        console.log(`[Vector DB] ✅ Returning ${topResults.length} most relevant chunks`)
        
        return topResults
    } catch (error) {
        console.error(`[Vector DB] ❌ Search failed: ${error.message}`)
        console.error(`[Vector DB] ❌ Error stack: ${error.stack}`)
        return []
    }
}

/**
 * Delete document from vector database
 * @param {string} documentId - Document ID to delete
 */
export async function deleteDocument(documentId) {
    if (!isVectorDBAvailable()) {
        return false
    }

    try {
        // Get all chunks for this document
        const results = await documentsCollection.get({
            where: { documentId },
        })

        if (results.ids && results.ids.length > 0) {
            await documentsCollection.delete({
                ids: results.ids,
            })
            console.log(
                `[Vector DB] ✅ Deleted ${results.ids.length} chunks for document ${documentId}`
            )
            return true
        }

        return false
    } catch (error) {
        console.error(`[Vector DB] ❌ Failed to delete document: ${error.message}`)
        return false
    }
}

/**
 * Get all documents for a user
 * @param {string} userId - User ID
 * @returns {Promise<Array<object>>}
 */
export async function getUserDocuments(userId) {
    if (!isVectorDBAvailable()) {
        return []
    }

    try {
        const results = await documentsCollection.get({
            where: { userId },
        })

        // Extract unique document IDs
        const documentIds = new Set()
        if (results.metadatas) {
            results.metadatas.forEach((meta) => {
                if (meta.documentId) {
                    documentIds.add(meta.documentId)
                }
            })
        }

        return Array.from(documentIds).map((docId) => {
            // Get metadata from first chunk of each document
            const docMetadata = results.metadatas.find(
                (meta) => meta.documentId === docId
            )
            return {
                documentId: docId,
                ...docMetadata,
            }
        })
    } catch (error) {
        console.error(`[Vector DB] ❌ Failed to get user documents: ${error.message}`)
        return []
    }
}

