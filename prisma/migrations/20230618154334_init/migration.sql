-- CreateTable
CREATE TABLE "Event" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "pubkey" TEXT NOT NULL,
    "created_at" INTEGER NOT NULL,
    "content" TEXT NOT NULL,
    "tags" TEXT NOT NULL,
    "sig" TEXT NOT NULL
);
