package com.inductiveautomation.metro.api;

import java.io.Serializable;

public class ServerId implements Serializable {
    private static final long serialVersionUID = 1L;

    private String address;
    private Role role;

    public ServerId(String serverAddress) {
        this.role = Role.Unspecified;
        this.address = serverAddress;
    }

    public ServerId(String serverAddress, Role role) {
        this.role = Role.Unspecified;
        this.address = serverAddress;
        this.role = role;
    }

    public String getServerName() {
        return this.address;
    }

    public Role getRole() {
        return this.role;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ServerId serverId = (ServerId) o;
        if (!this.address.equalsIgnoreCase(serverId.address)) return false;
        return this.role == serverId.role;
    }

    @Override
    public int hashCode() {
        int result = this.address.toLowerCase().hashCode();
        result = 31 * result + this.role.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return String.format("_0:%d:%s", this.role.ordinal(), this.address);
    }

    public static enum Role {
        Unspecified,
        Master,
        Backup;
    }
}
