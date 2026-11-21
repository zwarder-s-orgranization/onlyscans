"use client";

import { createContext, useContext, useState, type ReactNode } from "react";
import type { UserRole } from "@/data/workflows-workspace-data";

interface WorkspacePreviewContextValue {
  role: UserRole;
  setRole: (role: UserRole) => void;
  email: string;
  setEmail: (email: string) => void;
  forceEmpty: boolean;
  setForceEmpty: (value: boolean) => void;
}

const WorkspacePreviewContext = createContext<WorkspacePreviewContextValue>({
  role: "owner",
  setRole: () => {},
  email: "",
  setEmail: () => {},
  forceEmpty: false,
  setForceEmpty: () => {},
});

export function WorkspacePreviewProvider({ children }: { children: ReactNode }) {
  const [role, setRole] = useState<UserRole>("owner");
  const [email, setEmail] = useState("");
  const [forceEmpty, setForceEmpty] = useState(false);

  return (
    <WorkspacePreviewContext.Provider
      value={{
        role,
        setRole,
        email,
        setEmail,
        forceEmpty,
        setForceEmpty,
      }}
    >
      {children}
    </WorkspacePreviewContext.Provider>
  );
}

export function useWorkspacePreview() {
  return useContext(WorkspacePreviewContext);
}
