import {
	CertAuthProtocolExtension as EpxCertAuthProtocolExtension,
	CertAuthProtocolExtensionBuilder as EpxCertAuthProtocolExtensionBuilder,
	CertAuthProtocolExtensionBuilderRef as EpxCertAuthProtocolExtensionBuilderRef,
	MotdProtocolExtension as EpxMotdProtocolExtension,
	MotdProtocolExtensionBuilder as EpxMotdProtocolExtensionBuilder,
	MotdProtocolExtensionBuilderRef as EpxMotdProtocolExtensionBuilderRef,
	PasswordProtocolExtension as EpxPasswordProtocolExtension,
	PasswordProtocolExtensionBuilder as EpxPasswordProtocolExtensionBuilder,
	PasswordProtocolExtensionBuilderRef as EpxPasswordProtocolExtensionBuilderRef,
	UdpProtocolExtension as EpxUdpProtocolExtension,
	UdpProtocolExtensionBuilder as EpxUdpProtocolExtensionBuilder,
	UdpProtocolExtensionBuilderRef as EpxUdpProtocolExtensionBuilderRef,
	ProtocolExtensionBuilders,
} from "epoxy/wbg";

import { ProtocolExtension, ProtocolExtensionBuilder } from "./js";

export class UdpProtocolExtensionBuilder extends ProtocolExtensionBuilder {
	inner: EpxUdpProtocolExtensionBuilder;
	static readonly ID = 0x01;
	readonly id = UdpProtocolExtensionBuilder.ID;

	private constructor(inner: EpxUdpProtocolExtensionBuilder) {
		super();
		this.inner = inner;
	}

	static client(): UdpProtocolExtensionBuilder {
		return new UdpProtocolExtensionBuilder(
			EpxUdpProtocolExtensionBuilder.new_client()
		);
	}

	static server(): UdpProtocolExtensionBuilder {
		return new UdpProtocolExtensionBuilder(
			EpxUdpProtocolExtensionBuilder.new_server()
		);
	}

	appendTo(builders: ProtocolExtensionBuilders) {
		builders.udp(this.inner);
	}
}

export class UdpProtocolExtensionBuilderRef extends ProtocolExtensionBuilder {
	inner: EpxUdpProtocolExtensionBuilderRef;
	readonly id = 0x01;

	constructor(inner: EpxUdpProtocolExtensionBuilderRef) {
		super();
		this.inner = inner;
	}

	appendTo(_builders: ProtocolExtensionBuilders) {
		throw new Error("Cannot serialize extension builder refs into a handshake");
	}
}

export class UdpProtocolExtension extends ProtocolExtension {
	inner: EpxUdpProtocolExtension;
	readonly id = 0x01;

	constructor(inner: EpxUdpProtocolExtension) {
		super();
		this.inner = inner;
	}
}

export class MotdProtocolExtensionBuilder extends ProtocolExtensionBuilder {
	inner: EpxMotdProtocolExtensionBuilder;
	static readonly ID = 0x04;
	readonly id = MotdProtocolExtensionBuilder.ID;

	private constructor(inner: EpxMotdProtocolExtensionBuilder) {
		super();
		this.inner = inner;
	}

	static client(): MotdProtocolExtensionBuilder {
		return new MotdProtocolExtensionBuilder(
			EpxMotdProtocolExtensionBuilder.new_client()
		);
	}

	static server(motd: string): MotdProtocolExtensionBuilder {
		return new MotdProtocolExtensionBuilder(
			EpxMotdProtocolExtensionBuilder.new_server(motd)
		);
	}

	appendTo(builders: ProtocolExtensionBuilders) {
		builders.motd(this.inner);
	}
}

export class MotdProtocolExtensionBuilderRef extends ProtocolExtensionBuilder {
	inner: EpxMotdProtocolExtensionBuilderRef;
	readonly id = 0x04;

	constructor(inner: EpxMotdProtocolExtensionBuilderRef) {
		super();
		this.inner = inner;
	}

	appendTo(_builders: ProtocolExtensionBuilders) {
		throw new Error("Cannot serialize extension builder refs into a handshake");
	}

	get motd(): string | undefined {
		const motd = this.inner.motd();
		return motd === undefined || motd === null ? undefined : motd;
	}

	get isClient(): boolean {
		return this.inner.is_client();
	}
}

export class MotdProtocolExtension extends ProtocolExtension {
	inner: EpxMotdProtocolExtension;
	readonly id = 0x04;

	constructor(inner: EpxMotdProtocolExtension) {
		super();
		this.inner = inner;
	}

	get motd(): string {
		return this.inner.motd();
	}
}

export class PasswordProtocolExtensionBuilder extends ProtocolExtensionBuilder {
	inner: EpxPasswordProtocolExtensionBuilder;
	static readonly ID = 0x02;
	readonly id = PasswordProtocolExtensionBuilder.ID;

	private constructor(inner: EpxPasswordProtocolExtensionBuilder) {
		super();
		this.inner = inner;
	}

	static client(
		user?: string,
		password?: string
	): PasswordProtocolExtensionBuilder {
		return new PasswordProtocolExtensionBuilder(
			EpxPasswordProtocolExtensionBuilder.new_client(user, password)
		);
	}

	static server(required = false): PasswordProtocolExtensionBuilder {
		return new PasswordProtocolExtensionBuilder(
			EpxPasswordProtocolExtensionBuilder.new_server(required)
		);
	}

	appendTo(builders: ProtocolExtensionBuilders) {
		builders.password(this.inner);
	}
}

export class PasswordProtocolExtensionBuilderRef extends ProtocolExtensionBuilder {
	inner: EpxPasswordProtocolExtensionBuilderRef;
	readonly id = 0x02;

	constructor(inner: EpxPasswordProtocolExtensionBuilderRef) {
		super();
		this.inner = inner;
	}

	appendTo(_builders: ProtocolExtensionBuilders) {
		throw new Error("Cannot serialize extension builder refs into a handshake");
	}

	get required(): boolean | undefined {
		const required = this.inner.is_required();
		return required === undefined || required === null ? undefined : required;
	}
}

export class PasswordProtocolExtension extends ProtocolExtension {
	inner: EpxPasswordProtocolExtension;
	readonly id = 0x02;

	constructor(inner: EpxPasswordProtocolExtension) {
		super();
		this.inner = inner;
	}

	get required(): boolean | undefined {
		const required = this.inner.required();
		return required === undefined || required === null ? undefined : required;
	}

	get user(): string | undefined {
		const user = this.inner.user();
		return user === undefined || user === null ? undefined : user;
	}

	get chosenUser(): string | undefined {
		const user = this.inner.chosen_user();
		return user === undefined || user === null ? undefined : user;
	}
}

export class CertAuthProtocolExtensionBuilder extends ProtocolExtensionBuilder {
	inner: EpxCertAuthProtocolExtensionBuilder;
	static readonly ID = 0x03;
	readonly id = CertAuthProtocolExtensionBuilder.ID;

	private constructor(inner: EpxCertAuthProtocolExtensionBuilder) {
		super();
		this.inner = inner;
	}

	static client(): CertAuthProtocolExtensionBuilder {
		return new CertAuthProtocolExtensionBuilder(
			EpxCertAuthProtocolExtensionBuilder.new_client()
		);
	}

	static server(required = false): CertAuthProtocolExtensionBuilder {
		return new CertAuthProtocolExtensionBuilder(
			EpxCertAuthProtocolExtensionBuilder.new_server(required)
		);
	}

	appendTo(builders: ProtocolExtensionBuilders) {
		builders.cert(this.inner);
	}
}

export class CertAuthProtocolExtensionBuilderRef extends ProtocolExtensionBuilder {
	inner: EpxCertAuthProtocolExtensionBuilderRef;
	readonly id = 0x03;

	constructor(inner: EpxCertAuthProtocolExtensionBuilderRef) {
		super();
		this.inner = inner;
	}

	appendTo(_builders: ProtocolExtensionBuilders) {
		throw new Error("Cannot serialize extension builder refs into a handshake");
	}

	get required(): boolean | undefined {
		const required = this.inner.is_required();
		return required === undefined || required === null ? undefined : required;
	}
}

export class CertAuthProtocolExtension extends ProtocolExtension {
	inner: EpxCertAuthProtocolExtension;
	readonly id = 0x03;

	constructor(inner: EpxCertAuthProtocolExtension) {
		super();
		this.inner = inner;
	}

	get required(): boolean | undefined {
		const required = this.inner.required();
		return required === undefined || required === null ? undefined : required;
	}
}

export function wrapBuiltinExtension(
	raw: unknown
): ProtocolExtension | undefined {
	if (raw instanceof EpxUdpProtocolExtension)
		return new UdpProtocolExtension(raw);
	if (raw instanceof EpxMotdProtocolExtension)
		return new MotdProtocolExtension(raw);
	if (raw instanceof EpxPasswordProtocolExtension)
		return new PasswordProtocolExtension(raw);
	if (raw instanceof EpxCertAuthProtocolExtension)
		return new CertAuthProtocolExtension(raw);

	return;
}
