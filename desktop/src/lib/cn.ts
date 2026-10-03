import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/** Class names, later ones winning over earlier Tailwind classes they
 * conflict with (`cn("p-2", big && "p-4")`). */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
