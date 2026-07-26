--
-- PostgreSQL database dump
--

-- Dumped from database version 16.14 (Debian 16.14-1.pgdg13+1)
-- Dumped by pg_dump version 16.14 (Debian 16.14-1.pgdg13+1)

--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
                                   id uuid NOT NULL,
                                   audit_log_action character varying(50) NOT NULL,
                                   actor_user_id uuid,
                                   created_at timestamp(6) with time zone NOT NULL,
                                   ip_address character varying(45),
                                   target character varying(255) NOT NULL,
                                   tenant_id uuid NOT NULL,
                                   CONSTRAINT audit_logs_audit_log_action_check CHECK (((audit_log_action)::text = ANY ((ARRAY['LOGIN_SUCCESS'::character varying, 'LOGIN_FAILURE'::character varying, 'LOGOUT'::character varying, 'TOKEN_ISSUED'::character varying, 'TOKEN_REFRESHED'::character varying, 'TOKEN_REVOKED'::character varying, 'TOKEN_REUSE_DETECTED'::character varying, 'MFA_ENABLED'::character varying, 'MFA_DISABLED'::character varying, 'CLIENT_CREATED'::character varying, 'RATE_LIMIT_EXCEEDED'::character varying])::text[])))
);


--
-- Name: client_app_grant_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_app_grant_types (
                                               client_app_id uuid NOT NULL,
                                               grant_type character varying(255) NOT NULL
);


--
-- Name: client_app_redirect_uris; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_app_redirect_uris (
                                                 client_app_id uuid NOT NULL,
                                                 redirect_uri character varying(255) NOT NULL
);


--
-- Name: client_app_scopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_app_scopes (
                                          client_app_id uuid NOT NULL,
                                          scope character varying(255) NOT NULL
);


--
-- Name: client_apps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_apps (
                                    id uuid NOT NULL,
                                    client_id uuid NOT NULL,
                                    client_secret_hash character varying(255) NOT NULL,
                                    created_at timestamp(6) with time zone NOT NULL,
                                    name character varying(255),
                                    require_pkce boolean NOT NULL,
                                    tenant_id uuid NOT NULL,
                                    updated_at timestamp(6) with time zone NOT NULL
);


--
-- Name: mfa_recovery_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mfa_recovery_codes (
                                           mfa_secret_id uuid NOT NULL,
                                           recovery_code character varying(255) NOT NULL
);


--
-- Name: mfa_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mfa_secrets (
                                    id uuid NOT NULL,
                                    confirmed boolean NOT NULL,
                                    created_at timestamp(6) with time zone NOT NULL,
                                    encrypted_secret character varying(255) NOT NULL,
                                    user_id uuid NOT NULL
);


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
                                    id uuid NOT NULL,
                                    created_at timestamp(6) with time zone NOT NULL,
                                    description character varying(255),
                                    name character varying(64) NOT NULL
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
                                       id uuid NOT NULL,
                                       client_id uuid NOT NULL,
                                       created_at timestamp(6) with time zone NOT NULL,
                                       expires_at timestamp(6) with time zone NOT NULL,
                                       family_id uuid NOT NULL,
                                       parent_id uuid,
                                       status character varying(20) NOT NULL,
                                       token_hash character varying(255) NOT NULL,
                                       user_id uuid NOT NULL,
                                       CONSTRAINT refresh_tokens_status_check CHECK (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'ROTATED'::character varying, 'REVOKED'::character varying, 'EXPIRED'::character varying])::text[])))
);


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permissions (
                                         role_id uuid NOT NULL,
                                         permission_id uuid NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
                              id uuid NOT NULL,
                              created_at timestamp(6) with time zone NOT NULL,
                              name character varying(64) NOT NULL,
                              tenant_id uuid NOT NULL,
                              updated_at timestamp(6) with time zone NOT NULL
);


--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_roles (
                                   user_id uuid NOT NULL,
                                   role_id uuid NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
                              id uuid NOT NULL,
                              created_at timestamp(6) with time zone NOT NULL,
                              display_name character varying(150),
                              email character varying(255) NOT NULL,
                              enabled boolean NOT NULL,
                              locked boolean NOT NULL,
                              mfa_enabled boolean NOT NULL,
                              password_hash character varying(255) NOT NULL,
                              tenant_id uuid NOT NULL,
                              updated_at timestamp(6) with time zone NOT NULL
);



--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: client_apps client_apps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_apps
    ADD CONSTRAINT client_apps_pkey PRIMARY KEY (id);


--
-- Name: mfa_secrets mfa_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_secrets
    ADD CONSTRAINT mfa_secrets_pkey PRIMARY KEY (id);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: mfa_secrets uk_mfa_secret_user; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_secrets
    ADD CONSTRAINT uk_mfa_secret_user UNIQUE (user_id);


--
-- Name: roles uk_role_tenant_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT uk_role_tenant_name UNIQUE (tenant_id, name);


--
-- Name: users uk_user_tenant_email; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT uk_user_tenant_email UNIQUE (tenant_id, email);


--
-- Name: refresh_tokens uk_refresh_token_hash; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT uk_refresh_token_hash UNIQUE (token_hash);


--
-- Name: permissions uk_permission_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT uk_permission_name UNIQUE (name);


--
-- Name: client_apps uk_client_app_client_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_apps
    ADD CONSTRAINT uk_client_app_client_id UNIQUE (client_id);


--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: client_app_grant_types fk_client_app_grant_types_client_app; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_app_grant_types
    ADD CONSTRAINT fk_client_app_grant_types_client_app FOREIGN KEY (client_app_id) REFERENCES public.client_apps(id);


--
-- Name: mfa_secrets fk_mfa_secrets_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_secrets
    ADD CONSTRAINT fk_mfa_secrets_user FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: role_permissions fk_role_permissions_permission; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES public.permissions(id);


--
-- Name: client_app_redirect_uris fk_client_app_redirect_uris_client_app; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_app_redirect_uris
    ADD CONSTRAINT fk_client_app_redirect_uris_client_app FOREIGN KEY (client_app_id) REFERENCES public.client_apps(id);


--
-- Name: user_roles fk_user_roles_role; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES public.roles(id);


--
-- Name: user_roles fk_user_roles_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: mfa_recovery_codes fk_mfa_recovery_codes_mfa_secret; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_recovery_codes
    ADD CONSTRAINT fk_mfa_recovery_codes_mfa_secret FOREIGN KEY (mfa_secret_id) REFERENCES public.mfa_secrets(id);


--
-- Name: role_permissions fk_role_permissions_role; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES public.roles(id);


--
-- Name: client_app_scopes fk_client_app_scopes_client_app; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_app_scopes
    ADD CONSTRAINT fk_client_app_scopes_client_app FOREIGN KEY (client_app_id) REFERENCES public.client_apps(id);


CREATE INDEX idx_refresh_tokens_family_id ON public.refresh_tokens (family_id);

CREATE INDEX idx_audit_logs_tenant_created ON public.audit_logs (tenant_id, created_at DESC);
--
-- PostgreSQL database dump complete
--


