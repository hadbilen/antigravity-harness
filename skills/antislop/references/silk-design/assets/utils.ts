import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: (string | undefined | null | false)[]) {
  return inputs.filter(Boolean).join(" ");
}

export function cls(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
