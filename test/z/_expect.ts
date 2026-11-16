import { UnauthError } from "../../src/error.ts";

export function refused(run: () => unknown): UnauthError {
  try {
    run();
  } catch (error) {
    if (error instanceof UnauthError) return error;
    throw error;
  }
  throw new Error("Expected a refusal, got an answer.");
}
